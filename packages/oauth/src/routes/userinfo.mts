/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
	filterClaimsByScope,
	type KeyStore,
	type Logger,
	type RefreshTokenFamilyRevocation,
	type UserSessionStore,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export interface UserinfoRouterOptions {
	keyStore: KeyStore;
	userSessionStore?: UserSessionStore;
	refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
	/** Configured issuer — pinned by the SF-1 central verifier. */
	issuer?: string;
	/**
	 * SF-1 / Phase G / S2: when true, accept tokens whose `typ`
	 * header is absent (a `jwt_verify_legacy_typ` deprecation warning is
	 * emitted). the default is `false` (typ-less tokens rejected);
	 * `true` is an explicit legacy-acceptance opt-in for deployments
	 * still completing their v0.4.x rollover. The v0.5.x default was
	 * `true`.
	 */
	legacyTypAccept?: boolean;
	logger?: Logger;
}

/**
 * OIDC Core §5.3 — UserInfo Endpoint.
 *
 * Accepts Bearer access_token JWTs and returns scope-filtered claims from
 * the durable UserSession. Revocation is checked via family_id (cascade
 * revoke per F-3) and sid (session liveness).
 *
 * Error responses follow Bearer Token Usage (RFC 6750 §3.1): 401 with
 * WWW-Authenticate header. Fail-closed on store errors.
 */
export function createRouter(express: ExpressLike, opts: UserinfoRouterOptions): Router {
	const router = express.Router();

	const handleUserinfo = async (req: Request, res: Response) => {
		// RFC 6750 §5.3 + §6.1: bearer-authenticated responses MUST NOT be cached
		// by intermediaries. Set this once at the top so it applies to every
		// response path (200 success, 401 error).
		res.setHeader("Cache-Control", "no-store");
		res.setHeader("Pragma", "no-cache");

		// RFC 6750 §2.1: Bearer token in Authorization header
		const auth = req.headers.authorization;
		if (!auth?.startsWith("Bearer ")) {
			res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo"');
			return res
				.status(401)
				.json({ error: "invalid_token", error_description: "missing Bearer token" });
		}
		const token = auth.slice(7);

		// SF-1: alg / iss / typ + signature pinned by the central verifier
		// (typ: at+jwt is required per RFC 9068 since userinfo is an
		// access-token resource — OIDC Core §5.3.1). Audience pinning is
		// deferred: userinfo is bearer-as-credential and the calling-client
		// identity is not separately authenticated here, so the verifier
		// records the gap via `jwt_verify_aud_skipped`.
		let payload: Record<string, unknown>;
		try {
			const verified = await verifyJwt(token, opts.keyStore, {
				type: "access_token",
				expectedIssuer: opts.issuer ?? "",
				legacyTypAccept: opts.legacyTypAccept ?? false,
				logger: opts.logger,
			});
			payload = verified.payload as Record<string, unknown>;
		} catch {
			res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
			return res.status(401).json({ error: "invalid_token", error_description: "invalid token" });
		}

		// F-3 cascade revoke: check family_id against RefreshTokenStore.
		// Precondition: only activates when the JWT carries a family_id claim —
		// tokens minted before F-3 lack this claim and bypass the cascade check
		// (legacy backward-compat). New tokens always carry family_id per F-3.
		const familyId = typeof payload.family_id === "string" ? payload.family_id : null;
		if (familyId !== null && opts.refreshTokenFamilyRevocation) {
			let revoked: boolean;
			try {
				revoked = await opts.refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
			} catch {
				// Fail-closed: cannot determine revocation state → treat as revoked
				res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
				return res
					.status(401)
					.json({ error: "invalid_token", error_description: "revocation check unavailable" });
			}
			if (revoked) {
				res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
				return res
					.status(401)
					.json({ error: "invalid_token", error_description: "family revoked" });
			}
		}

		// sub is required; sid is optional (needed for session-backed claims —
		// when absent or no userSessionStore wired, we return {sub} only).
		const sub = typeof payload.sub === "string" ? payload.sub : null;
		const sid = typeof payload.sid === "string" ? payload.sid : null;
		if (!sub) {
			res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
			return res
				.status(401)
				.json({ error: "invalid_token", error_description: "missing sub claim" });
		}

		// Without a session store, return only sub (no durable claim source)
		if (!opts.userSessionStore || !sid) {
			return res.status(200).json({ sub });
		}

		// Validate session liveness. Fail-closed on store throw (symmetric with
		// the refreshTokenStore cascade above): a backend outage must not leak
		// claims, and returning 401 invalid_token keeps parity with RFC 6750.
		let session: Awaited<ReturnType<typeof opts.userSessionStore.get>>;
		try {
			session = await opts.userSessionStore.get(sid);
		} catch {
			res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
			return res
				.status(401)
				.json({ error: "invalid_token", error_description: "session lookup unavailable" });
		}
		if (!session) {
			res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
			return res.status(401).json({ error: "invalid_token", error_description: "session_invalid" });
		}

		// Return sub + scope-filtered claims per OIDC Core §5.4
		const scopes =
			typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : [];
		const filtered = filterClaimsByScope(session.claims, scopes);
		return res.status(200).json({ sub, ...filtered });
	};

	router.get("/userinfo", handleUserinfo);
	router.post("/userinfo", handleUserinfo);

	return router;
}
