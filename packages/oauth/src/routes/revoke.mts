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
	type AccessTokenDenylist,
	type ClientRepository,
	type KeyStore,
	type Logger,
	type RefreshTokenFamilyRevocation,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
import { createClientAuthMiddleware } from "../middleware/clientAuth.mjs";

type ExpressLike = {
	Router: () => Router;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export interface RevokeRouterOptions {
	readonly clientRepository: ClientRepository;
	readonly keyStore: KeyStore;
	readonly refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
	readonly accessTokenDenylist?: AccessTokenDenylist;
	readonly logger: Logger;
	readonly issuer: string;
}

/**
 * Creates an Express router handling `POST /revoke` per RFC 7009.
 *
 * Behavior summary:
 * - Requires client authentication (confidential clients only; public clients
 *   rejected per RFC 7009 §2.1 — see `allowPublicClients: false` default).
 * - Accepts `token` + optional `token_type_hint` form params.
 * - Returns 400 `invalid_request` when `token` is absent.
 * - Returns 400 `unsupported_token_type` when `token_type_hint` is present
 *   but not a recognized value.
 * - ALWAYS returns 200 for all other outcomes (RFC 7009 §2.2 no-info-leak).
 *
 * Refresh-token path:
 * - Verifies the RT signature / type / issuer via `verifyJwt`.
 * - Extracts `family_id` claim; if absent or verification fails → silent 200.
 * - Verifies client ownership via `azp` (falls back to `aud`).
 * - Calls `refreshTokenFamilyRevocation.revokeFamily(familyId)`.
 * - When `refreshTokenFamilyRevocation` slot is unwired → silent 200.
 *
 * Access-token path:
 * - Verifies AT signature / type / issuer with `ignoreExpiration: true`
 *   (the ONLY legitimate call site for this option — CI lint guardrail T7
 *   prevents drift to other sites).
 * - Extracts `jti`, `exp`, `client_id` (or `azp` fallback) from payload.
 * - Verifies client ownership; mismatch → silent 200.
 * - When `accessTokenDenylist` slot is wired: calls `denylist.add(jti, exp * 1000)`.
 * - When `accessTokenDenylist` slot is unwired: logs warn + silent 200.
 */
export function createRevokeRouter(express: ExpressLike, opts: RevokeRouterOptions): Router {
	const router = express.Router();
	router.use(express.urlencoded({ extended: false }));

	const clientAuth = createClientAuthMiddleware(opts.clientRepository, {
		issuer: opts.issuer,
		logger: opts.logger,
		// RFC 7009 §2.1: public clients may revoke their own tokens.
		// Wave 1 default: reject public clients (matches spec §4.4 Wave 1 note).
		// Revisit when dogfood surface requires it.
		allowPublicClients: false,
	});

	router.post("/revoke", clientAuth, async (req, res) => {
		const body = (req.body ?? {}) as Record<string, string | undefined>;
		const { token, token_type_hint } = body;

		if (!token) {
			res
				.status(400)
				.json({ error: "invalid_request", error_description: "token form param is required" });
			return;
		}

		if (
			token_type_hint !== undefined &&
			token_type_hint !== "access_token" &&
			token_type_hint !== "refresh_token"
		) {
			res.status(400).json({ error: "unsupported_token_type" });
			return;
		}

		// Defensive: clientAuth sets req.oauthClient before calling next().
		// Absent only if middleware is misconfigured; bail silently to avoid 500.
		const client = req.oauthClient;
		if (!client) {
			res.status(200).end();
			return;
		}

		// Per RFC 7009 §2.1: try the type matching the hint first; on failure or
		// when no hint is given, try the other type. "try" here means "attempt to
		// interpret the token as that type; on any failure silently move on".
		const tryRefreshFirst = token_type_hint !== "access_token";
		const tryAccessFirst = token_type_hint === "access_token";

		if (tryRefreshFirst) {
			const revoked = await tryRevokeRefreshToken(token, client.clientId, opts);
			if (revoked) {
				res.status(200).end();
				return;
			}
		}

		if (tryAccessFirst || token_type_hint === undefined) {
			await tryRevokeAccessToken(token, client.clientId, opts);
		}

		// RFC 7009 §2.2: always 200 regardless of whether the token existed.
		res.status(200).end();
	});

	return router;
}

/**
 * Attempt to revoke a refresh token.
 *
 * Returns `true` if revocation was performed (the RT was valid and belonged to
 * the requesting client). Returns `false` for any other outcome — caller
 * should then try the access-token path or return 200 silently.
 */
async function tryRevokeRefreshToken(
	token: string,
	requestingClientId: string,
	opts: RevokeRouterOptions,
): Promise<boolean> {
	if (!opts.refreshTokenFamilyRevocation) {
		return false;
	}
	try {
		const verified = await verifyJwt(token, opts.keyStore, {
			type: "refresh_token",
			expectedIssuer: opts.issuer,
			// Do NOT ignore expiration for RTs — an expired RT cannot be "revoked"
			// in a meaningful security sense (it is already invalid), but we do
			// NOT return false here; revoking an expired-but-valid-sig RT is
			// harmless idempotency and keeps the family revoked for cascade checks.
			// `ignoreExpiration` is intentionally absent (only valid in AT path).
		});
		const claims = verified.payload as Record<string, unknown>;

		// Extract family_id — present on tokens minted by v0.5.x+.
		const familyIdRaw = claims.family_id;
		const familyId = typeof familyIdRaw === "string" && familyIdRaw.length > 0 ? familyIdRaw : null;
		if (!familyId) {
			// No family_id → legacy token; cannot revoke by family.
			return false;
		}

		// Verify client ownership: azp takes precedence (D-6 PB-2); fall back to aud.
		const tokenAud = Array.isArray(verified.payload.aud)
			? verified.payload.aud[0]
			: verified.payload.aud;
		const tokenAzp =
			typeof claims.azp === "string" && claims.azp.length > 0 ? claims.azp : tokenAud;
		if (tokenAzp !== requestingClientId) {
			// Wrong owner — silent 200 (RFC 7009 §2.2 no-info-leak).
			return false;
		}

		await opts.refreshTokenFamilyRevocation.revokeFamily(familyId);
		return true;
	} catch {
		// Invalid signature / wrong type / wrong issuer → silent 200.
		opts.logger?.debug?.(
			{ scope: "oauth.revoke.refresh" },
			"refresh token revoke skipped (verification failed)",
		);
		return false;
	}
}

/**
 * Attempt to revoke an access token by adding its jti to the denylist.
 *
 * Always resolves (never throws) — failures are logged and swallowed.
 * `ignoreExpiration: true` is intentional and is the ONLY legitimate call site
 * for this option in production code (CI guardrail T7 enforces this).
 */
async function tryRevokeAccessToken(
	token: string,
	requestingClientId: string,
	opts: RevokeRouterOptions,
): Promise<void> {
	if (!opts.accessTokenDenylist) {
		opts.logger.warn(
			{ scope: "oauth.revoke.access" },
			"AT revocation requested but accessTokenDenylist slot is unwired; no-op",
		);
		return;
	}
	try {
		// ignoreExpiration: true — §4.5 / S9. Revoking an already-expired AT is
		// harmless and semantically correct: the client may not know the AT has
		// expired, and this is the ONLY call site where this option is permitted.
		const verified = await verifyJwt(token, opts.keyStore, {
			type: "access_token",
			expectedIssuer: opts.issuer,
			ignoreExpiration: true,
		});
		const claims = verified.payload as Record<string, unknown>;

		const jti = typeof verified.payload.jti === "string" ? verified.payload.jti : undefined;
		const exp = typeof verified.payload.exp === "number" ? verified.payload.exp : undefined;

		if (!jti || !exp) {
			// Malformed AT (no jti or exp) — cannot denylist; silent 200.
			opts.logger.debug({ scope: "oauth.revoke.access" }, "AT revoke skipped: missing jti or exp");
			return;
		}

		// Verify client ownership: client_id claim (RFC 9068) or azp fallback.
		const tokenAud = Array.isArray(verified.payload.aud)
			? verified.payload.aud[0]
			: verified.payload.aud;
		const rawClientId = claims.client_id;
		const rawAzp = claims.azp;
		const tokenClientId =
			typeof rawClientId === "string" && rawClientId.length > 0
				? rawClientId
				: typeof rawAzp === "string" && rawAzp.length > 0
					? rawAzp
					: tokenAud;

		if (tokenClientId !== undefined && tokenClientId !== requestingClientId) {
			// Wrong owner — silent 200 (RFC 7009 §2.2 no-info-leak).
			opts.logger.debug(
				{ scope: "oauth.revoke.access", expected: requestingClientId, got: tokenClientId },
				"AT revoke skipped: client_id mismatch",
			);
			return;
		}

		await opts.accessTokenDenylist.add(jti, exp * 1000);
	} catch {
		// Invalid signature / wrong type / wrong issuer → silent 200.
		opts.logger.debug({ scope: "oauth.revoke.access" }, "AT revoke skipped (verification failed)");
	}
}
