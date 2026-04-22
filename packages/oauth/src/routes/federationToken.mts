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

import type {
	AuditSinkBase,
	ClientRepository,
	FederationProviderHandle,
	FederationTokenStoreBase,
	KeyStore,
	Logger,
	RefreshTokenStoreBase,
	UserSessionStoreBase,
} from "@o3co/auth-provider-core";
import { emitAuditEvent, supportsLock } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { decodeProtectedHeader, jwtVerify } from "jose";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

/**
 * Structural narrowing of `FederationProviderHandle` for the refresh capability.
 * Local duck-type guard that mirrors `supportsRefresh` from @o3co/auth-provider-session,
 * defined here to keep the oauth package independent of session.
 */
interface SupportsRefreshShape {
	refreshFederationToken(refreshToken: string): Promise<{
		accessToken: string;
		refreshToken?: string;
		idToken?: string;
		/**
		 * Absolute expiry of refreshed `accessToken`. `null` means the upstream
		 * provider issued a non-expiring replacement (rare, but legal under RFC 6749
		 * §5.1 where `expires_in` is optional). Mirrors session's
		 * `FederationProfile.expiresAt` contract so adapters stay consistent across
		 * issue and refresh paths.
		 */
		expiresAt: Date | null;
	}>;
}

/**
 * Duck-type guard: does `provider` expose a `refreshFederationToken` method?
 * Returns `false` for null/undefined so callers can pass Map.get() results directly.
 */
function supportsRefresh(
	provider: FederationProviderHandle | undefined | null,
): provider is FederationProviderHandle & SupportsRefreshShape {
	if (provider == null) return false;
	return (
		typeof (provider as { refreshFederationToken?: unknown }).refreshFederationToken === "function"
	);
}

export interface FederationTokenRouterOptions {
	keyStore: KeyStore;
	refreshTokenStore: RefreshTokenStoreBase;
	userSessionStore: UserSessionStoreBase;
	federationTokenStore: FederationTokenStoreBase;
	clientRepository: ClientRepository;
	/**
	 * Getter for the federation providers Map. Evaluated at request time (not at
	 * router construction time) so module init order does not matter.
	 * Returns undefined when federation is not configured.
	 */
	getFederationProviders: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
	/** Audit sink for operator observability events. No-op when undefined. */
	auditSink?: AuditSinkBase;
	/** Structured logger. Defaults to console when undefined. */
	logger?: Logger;
	/**
	 * Tokens within this many milliseconds of expiry are proactively refreshed.
	 * Default: 30_000 (30 seconds).
	 */
	refreshBufferMs?: number;
}

/**
 * POST /federation/:name/token — Federation token proxy endpoint (TODO-F-6).
 *
 * Allows opt-in clients to retrieve the user's upstream federation access_token.
 * The caller must present a valid at+jwt access token in the Authorization header.
 * The client identified by `azp` must have `allowedAzpForFederationToken: true`.
 *
 * Mounted under /oauth → POST /oauth/federation/:name/token.
 */
export function createRouter(express: ExpressLike, opts: FederationTokenRouterOptions): Router {
	const router = express.Router();

	router.post("/federation/:name/token", async (req: Request, res: Response) => {
		const { name } = req.params as { name: string };
		const logger = opts.logger ?? console;
		const refreshBufferMs = opts.refreshBufferMs ?? 30_000;

		// RFC 6749 §5.1 / RFC 9207: cache headers on every response path.
		res.setHeader("Cache-Control", "no-store");
		res.setHeader("Pragma", "no-cache");

		// Step 1: Extract Bearer access_token from Authorization header.
		const auth = req.headers.authorization;
		if (!auth || !/^Bearer /i.test(auth)) {
			res.setHeader(
				"WWW-Authenticate",
				'Bearer error="invalid_token", error_description="missing Bearer token"',
			);
			return res
				.status(401)
				.json({ error: "invalid_token", error_description: "missing Bearer token" });
		}
		const token = auth.slice(auth.indexOf(" ") + 1);

		// Step 2 + 3: Verify JWT signature + check typ === "at+jwt".
		let payload: Record<string, unknown>;
		try {
			const header = decodeProtectedHeader(token);
			if (header.typ !== "at+jwt") {
				throw new Error("invalid token type");
			}
			const key = await opts.keyStore.getVerificationKey(
				header.kid ?? opts.keyStore.getSigningKidFallback(),
			);
			const verified = await jwtVerify(token, key);
			payload = verified.payload as Record<string, unknown>;
		} catch (error) {
			logger.warn(
				`POST /oauth/federation/${name}/token: jwtVerify failed:`,
				error instanceof Error ? error.message : String(error),
			);
			res.setHeader(
				"WWW-Authenticate",
				'Bearer error="invalid_token", error_description="invalid token"',
			);
			return res.status(401).json({
				error: "invalid_token",
				error_description: "invalid token",
			});
		}

		// Step 4: Extract family_id, sid, azp from payload.
		const familyId = typeof payload.family_id === "string" ? payload.family_id : null;
		const sid = typeof payload.sid === "string" ? payload.sid : null;
		const azp = typeof payload.azp === "string" ? payload.azp : null;
		const sub = typeof payload.sub === "string" ? payload.sub : null;

		if (!familyId) {
			res.setHeader(
				"WWW-Authenticate",
				'Bearer error="invalid_token", error_description="missing family_id claim"',
			);
			return res
				.status(401)
				.json({ error: "invalid_token", error_description: "missing family_id claim" });
		}
		if (!sid) {
			res.setHeader(
				"WWW-Authenticate",
				'Bearer error="invalid_token", error_description="missing sid claim"',
			);
			return res
				.status(401)
				.json({ error: "invalid_token", error_description: "missing sid claim" });
		}
		if (!azp) {
			res.setHeader(
				"WWW-Authenticate",
				'Bearer error="invalid_token", error_description="missing azp claim"',
			);
			return res
				.status(401)
				.json({ error: "invalid_token", error_description: "missing azp claim" });
		}

		// Step 5: Check family revocation. Fail-closed: any throw → 401.
		let revoked: boolean;
		try {
			revoked = await opts.refreshTokenStore.isFamilyRevoked(familyId);
		} catch (error) {
			logger.warn(
				`POST /oauth/federation/${name}/token: isFamilyRevoked failed (refresh store outage):`,
				error,
			);
			res.setHeader(
				"WWW-Authenticate",
				'Bearer error="invalid_token", error_description="revocation check unavailable"',
			);
			return res.status(401).json({
				error: "invalid_token",
				error_description: "revocation check unavailable",
			});
		}
		if (revoked) {
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "federation.token.family_revoked",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { sid },
			});
			res.setHeader(
				"WWW-Authenticate",
				'Bearer error="invalid_token", error_description="family revoked"',
			);
			return res.status(401).json({
				error: "invalid_token",
				error_description: "family revoked",
			});
		}

		// Step 6: Load session. null → 401 invalid_token. Throw → 503.
		let session: Awaited<ReturnType<typeof opts.userSessionStore.get>>;
		try {
			session = await opts.userSessionStore.get(sid);
		} catch (error) {
			logger.warn(`POST /oauth/federation/${name}/token: userSessionStore.get failed:`, error);
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
		}
		if (!session) {
			res.setHeader(
				"WWW-Authenticate",
				'Bearer error="invalid_token", error_description="session not found"',
			);
			return res.status(401).json({
				error: "invalid_token",
				error_description: "session not found",
			});
		}

		// Step 7: Client must exist AND have allowedAzpForFederationToken === true.
		let client: Awaited<ReturnType<typeof opts.clientRepository.findById>>;
		try {
			client = await opts.clientRepository.findById(azp);
		} catch (error) {
			logger.warn(`POST /oauth/federation/${name}/token: clientRepository.findById failed:`, error);
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "client repository unavailable",
			});
		}
		if (!client || !client.allowedAzpForFederationToken) {
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "federation.token.forbidden",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { federation: name, azp },
			});
			return res.status(403).json({
				error: "forbidden",
				error_description: "client is not permitted to access federation tokens",
			});
		}

		// Step 8: Federation must be linked to this session.
		if (!session.federations.includes(name)) {
			return res.status(404).json({
				error: "federation_not_linked",
				error_description: `federation "${name}" is not linked to this session`,
			});
		}

		// Step 9: Get federation tokens. Throw → 503. null → self-heal + 404.
		let tokens: Awaited<ReturnType<typeof opts.federationTokenStore.get>>;
		try {
			tokens = await opts.federationTokenStore.get(sid, name);
		} catch (error) {
			logger.warn(`POST /oauth/federation/${name}/token: federationTokenStore.get failed:`, error);
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "federation token store unavailable",
			});
		}
		if (!tokens) {
			// Self-heal: federation link is dangling — remove from session state.
			try {
				await opts.userSessionStore.removeFederation(sid, name);
			} catch (error) {
				logger.warn(
					`POST /oauth/federation/${name}/token: removeFederation self-heal failed:`,
					error,
				);
				// Best-effort: still return 404 regardless
			}
			return res.status(404).json({
				error: "federation_not_linked",
				error_description: `federation "${name}" tokens not found`,
			});
		}

		// Step 10: If not expired (within buffer), return existing token.
		// `expiresAt === null` means the upstream provider issues no finite expiry
		// (e.g. GitHub OAuth Apps classic tokens). Treat as "never expired; never
		// refresh" — reuse the stored accessToken indefinitely, and omit the
		// `expires_in` field from the response (RFC 6749 §5.1 makes it optional).
		if (tokens.expiresAt === null || tokens.expiresAt.getTime() > Date.now() + refreshBufferMs) {
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "federation.token.success",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { federation: name, refreshed: false },
			});
			const expiresIn =
				tokens.expiresAt === null
					? undefined
					: Math.max(0, Math.floor((tokens.expiresAt.getTime() - Date.now()) / 1000));
			return res.status(200).json({
				access_token: tokens.accessToken,
				token_type: "Bearer",
				...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
				...(tokens.scope ? { scope: tokens.scope } : {}),
			});
		}

		// Step 11: Refresh path.

		// 11a: Get provider and check supportsRefresh.
		const provider = opts.getFederationProviders()?.get(name);
		if (!supportsRefresh(provider)) {
			logger.warn(
				`POST /oauth/federation/${name}/token: provider does not support refresh or not found`,
			);
			return res.status(503).json({
				error: "refresh_not_supported",
				error_description: `federation "${name}" does not support token refresh`,
			});
		}

		// 11b: refreshToken must be present.
		if (!tokens.refreshToken) {
			return res.status(410).json({
				error: "refresh_token_absent",
				error_description: "no refresh token available for this federation",
			});
		}

		// 11c: Acquire lock if supported.
		let release: (() => Promise<void>) | undefined;
		if (supportsLock(opts.federationTokenStore)) {
			let lockResult: Awaited<ReturnType<typeof opts.federationTokenStore.acquireLock>>;
			try {
				lockResult = await opts.federationTokenStore.acquireLock({
					sid,
					federationName: name,
				});
			} catch (error) {
				logger.warn(`POST /oauth/federation/${name}/token: acquireLock failed:`, error);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "federation token store unavailable",
				});
			}
			if (!lockResult.acquired) {
				return res.status(503).json({
					error: "lock_timeout",
					error_description: "could not acquire refresh lock, try again",
				});
			}
			release = lockResult.release;
		}

		try {
			// currentTokens tracks the freshest snapshot of stored federation tokens.
			// It starts as the pre-lock read and is updated to the post-lock re-read
			// value (11d) so that all downstream IdP calls and store writes use the
			// most up-to-date refresh_token and id_token — never a stale pre-lock snapshot.
			let currentTokens = tokens;

			// 11d: Re-read tokens after lock acquisition to detect concurrent refresh.
			if (release !== undefined) {
				let freshTokens: Awaited<ReturnType<typeof opts.federationTokenStore.get>>;
				try {
					freshTokens = await opts.federationTokenStore.get(sid, name);
				} catch (error) {
					logger.warn(
						`POST /oauth/federation/${name}/token: federationTokenStore.get (post-lock re-read) failed:`,
						error,
					);
					return res.status(503).json({
						error: "temporarily_unavailable",
						error_description: "federation token store unavailable",
					});
				}
				if (
					freshTokens &&
					(freshTokens.expiresAt === null ||
						freshTokens.expiresAt.getTime() > Date.now() + refreshBufferMs)
				) {
					// Another caller already refreshed, OR the provider issues no finite
					// expiry (expiresAt === null → never refresh): return the stored token
					// without calling IdP.
					const expiresIn =
						freshTokens.expiresAt === null
							? undefined
							: Math.max(0, Math.floor((freshTokens.expiresAt.getTime() - Date.now()) / 1000));
					emitAuditEvent(opts.auditSink, {
						timestamp: new Date(),
						type: "federation.token.success",
						subject: sub ?? undefined,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { federation: name, refreshed: false },
					});
					return res.status(200).json({
						access_token: freshTokens.accessToken,
						token_type: "Bearer",
						...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
						...(freshTokens.scope ? { scope: freshTokens.scope } : {}),
					});
				}
				// Update to the post-lock re-read value (may be freshTokens or null if
				// the store returned null; in either case currentTokens keeps the pre-lock
				// snapshot when freshTokens is null, which is the safest fallback).
				if (freshTokens) {
					currentTokens = freshTokens;
				}
			}

			// 11e: Call provider to refresh the federation token.
			// currentTokens now holds the freshest available snapshot — any post-lock
			// re-read value has been folded in above. This ensures we never call the IdP
			// with a stale (pre-lock, already-rotated) refresh_token.
			// The lock is held across the IdP refresh call. Lock TTL (default 5s per
			// AcquireLockOptions) SHOULD be >= IdP refresh timeout to avoid another
			// waiter acquiring mid-flight. If the IdP call exceeds TTL, a second
			// waiter will call the IdP too — not dangerous because federationTokenStore.update
			// is atomic and last-write-wins preserves a valid token, but operators
			// should tune ttlMs via the lock adapter config if their IdP is slow.
			let refreshed: Awaited<ReturnType<typeof provider.refreshFederationToken>>;
			try {
				refreshed = await provider.refreshFederationToken(currentTokens.refreshToken ?? "");
			} catch (error) {
				const msg = error instanceof Error ? error.message : String(error);
				logger.warn(`POST /oauth/federation/${name}/token: refreshFederationToken failed:`, error);

				// 11e → Step 12: Classify the error.
				if (msg.includes("invalid_grant")) {
					// Cleanup: delete federation token + remove federation link.
					try {
						await opts.federationTokenStore.delete(sid, name);
					} catch (cleanupErr) {
						logger.warn(
							`POST /oauth/federation/${name}/token: federationTokenStore.delete cleanup failed:`,
							cleanupErr,
						);
					}
					try {
						await opts.userSessionStore.removeFederation(sid, name);
					} catch (cleanupErr) {
						logger.warn(
							`POST /oauth/federation/${name}/token: removeFederation cleanup failed:`,
							cleanupErr,
						);
					}
					emitAuditEvent(opts.auditSink, {
						timestamp: new Date(),
						type: "federation.token.reauthentication_required",
						subject: sub ?? undefined,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { federation: name },
					});
					return res.status(410).json({
						error: "re_authentication_required",
						error_description: "federation re-authentication required",
					});
				}

				if (msg.includes("temporarily_unavailable") || /5\d\d/.test(msg)) {
					return res.status(503).json({
						error: "temporarily_unavailable",
						error_description: "upstream federation provider temporarily unavailable",
					});
				}

				emitAuditEvent(opts.auditSink, {
					timestamp: new Date(),
					type: "federation.token.refresh_failed",
					subject: sub ?? undefined,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: { federation: name, error: msg },
				});
				return res.status(500).json({
					error: "refresh_failed",
					error_description: "federation token refresh failed",
				});
			}

			// 11f: Update store — preserve refresh_token and id_token when IdP didn't rotate/return them.
			// Use currentTokens (post-lock re-read) as the fallback source so we never
			// revert to a stale pre-lock snapshot.
			const updatedTokens = {
				accessToken: refreshed.accessToken,
				refreshToken: refreshed.refreshToken ?? currentTokens.refreshToken,
				// IdPs like Google/GitHub typically don't return a new id_token on refresh.
				// Fall back to the stored id_token to preserve the id_token_hint for logout (F-5).
				idToken: refreshed.idToken ?? currentTokens.idToken,
				expiresAt: refreshed.expiresAt,
				tokenType: currentTokens.tokenType,
				scope: currentTokens.scope,
				rawParams: currentTokens.rawParams,
			};
			try {
				await opts.federationTokenStore.update(sid, name, updatedTokens);
			} catch (error) {
				logger.warn(
					`POST /oauth/federation/${name}/token: federationTokenStore.update failed:`,
					error,
				);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "federation token store unavailable",
				});
			}

			// 11h: Return refreshed token.
			// Mirror Step 10's contract: when `expiresAt === null` the provider refuses
			// to commit to a finite lifetime; omit `expires_in` from the RFC 6749 §5.1
			// response (the field is optional).
			const expiresIn =
				refreshed.expiresAt === null
					? undefined
					: Math.max(0, Math.floor((refreshed.expiresAt.getTime() - Date.now()) / 1000));
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "federation.token.success",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { federation: name, refreshed: true },
			});
			return res.status(200).json({
				access_token: refreshed.accessToken,
				token_type: "Bearer",
				...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
				...(currentTokens.scope ? { scope: currentTokens.scope } : {}),
			});
		} finally {
			// 11g: Release lock if acquired.
			if (release !== undefined) {
				try {
					await release();
				} catch (error) {
					logger.warn(`POST /oauth/federation/${name}/token: lock release failed:`, error);
				}
			}
		}
	});

	return router;
}
