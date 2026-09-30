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
	auditErrorText,
	BEARER_TOKEN_TYPE,
	emitAuditEvent,
	logClientRepositoryUnavailable,
	loggableError,
	sanitizeErrorText,
	supportsLock,
	supportsRefresh,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { identifyCaller } from "./federationTokenCaller.mjs";
import {
	createStoreUnavailableLog,
	type FederationTokenContext,
	type FederationTokenRouterOptions,
} from "./federationTokenContext.mjs";
import {
	mayDiscloseTokenType,
	refuseUndisclosableTokenType,
} from "./federationTokenDisclosure.mjs";
import { readRefreshAnswer } from "./federationTokenRefreshAnswer.mjs";
import { answerRefreshFailure } from "./federationTokenRefreshFailure.mjs";
import { recordRefresh } from "./federationTokenRefreshRecord.mjs";
import { answerStoredToken, readStoredTokens } from "./federationTokenStored.mjs";

export type { FederationTokenRouterOptions } from "./federationTokenContext.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

/**
 * POST /federation/:name/token — the federation token proxy. Returns the
 * user's upstream federation access token to an opted-in client: the caller
 * presents a valid at+jwt access token, and the client named by its `azp`
 * must have `allowedAzpForFederationToken: true`.
 *
 * Mounted under /oauth → POST /oauth/federation/:name/token.
 */
export function createRouter(express: ExpressLike, opts: FederationTokenRouterOptions): Router {
	const router = express.Router();

	router.post("/federation/:name/token", async (req: Request, res: Response) => {
		const { name } = req.params as { name: string };
		// The path parameter is the caller's text, logged before any membership
		// check: every log line and every audit event carries it sanitised and
		// capped, as a client id is — `federation.token.forbidden` fires before
		// the linked-federation check.
		const federation = auditErrorText(name);
		const logger = opts.logger ?? console;
		const storeUnavailable = createStoreUnavailableLog(logger);
		const refreshBufferMs = opts.refreshBufferMs ?? 30_000;

		// RFC 6749 §5.1 / RFC 9207: cache headers on every response path.
		res.setHeader("Cache-Control", "no-store");
		res.setHeader("Pragma", "no-cache");

		const ctx: FederationTokenContext = {
			opts,
			req,
			res,
			name,
			federation,
			logger,
			storeUnavailable,
			refreshBufferMs,
		};
		const caller = await identifyCaller(ctx);
		if (caller === null) return;
		const { familyId, sid, azp, sub } = caller;

		// Step 5: family revocation, fail-closed. A throw is `503`, never `401
		// invalid_token`, which would send the client to replace a token nobody
		// could judge (RFC 6750 §3.1).
		let revoked: boolean;
		try {
			revoked = await opts.refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
		} catch (error) {
			logger.error(
				{ federation, store: "refresh_token_family", err: loggableError(error) },
				"federation_token_store_unavailable",
			);
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "refresh token store unavailable",
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
			storeUnavailable(federation, "user_session", "get", error);
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

		// Read the federation index once, for the membership check and cleanup.
		let federations: ReadonlyArray<string>;
		try {
			federations = await opts.sessionFederationIndex.listFederations(sid);
		} catch (error) {
			storeUnavailable(federation, "session_federation_index", "list", error);
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
		}

		// Step 7: Client must exist AND have allowedAzpForFederationToken === true.
		let client: Awaited<ReturnType<typeof opts.clientRepository.findById>>;
		try {
			client = await opts.clientRepository.findById(azp);
		} catch (error) {
			logClientRepositoryUnavailable(
				logger,
				{ site: "federation_token", step: "find", clientId: azp },
				error,
			);
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "client repository unavailable",
			});
		}
		if (!client?.allowedAzpForFederationToken) {
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "federation.token.forbidden",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { federation, azp },
			});
			return res.status(403).json({
				error: "forbidden",
				error_description: "client is not permitted to access federation tokens",
			});
		}

		// Step 8: Federation must be linked to this session.
		if (!federations.includes(name)) {
			return res.status(404).json({
				error: "federation_not_linked",
				error_description: sanitizeErrorText(`federation '${name}' is not linked to this session`),
			});
		}

		const tokens = await readStoredTokens(ctx, caller);
		if (tokens === null) return;

		// Step 10: not expiring within the buffer → return the stored token.
		// `expiresAt === null` is an upstream issuing no finite expiry (e.g.
		// GitHub OAuth App tokens): never refresh, and omit `expires_in`.
		if (tokens.expiresAt === null || tokens.expiresAt.getTime() > Date.now() + refreshBufferMs) {
			return answerStoredToken(ctx, caller, tokens);
		}

		// Step 11: Refresh path.

		// 11a: Get provider and check supportsRefresh.
		const provider = opts.getFederationProviders()?.get(name);
		if (!supportsRefresh(provider)) {
			// The deployment's to fix, not a request's: every refresh through this
			// federation is answered 503 until the provider is configured.
			logger.error({ federation }, "federation_token_refresh_unsupported");
			return res.status(503).json({
				error: "refresh_not_supported",
				error_description: sanitizeErrorText(`federation '${name}' does not support token refresh`),
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
				storeUnavailable(federation, "federation_token", "acquire_lock", error);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "federation token store unavailable",
				});
			}
			if (!lockResult.acquired) {
				// Contention, not an outage: another refresh of this record holds
				// the lock. Warn, so contention that persists is seen — who waited
				// (the federation, the client, the session), never a token.
				logger.warn({ federation, clientId: azp, sid }, "federation_token_lock_timeout");
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
					storeUnavailable(federation, "federation_token", "get_after_lock", error);
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
					// Another caller refreshed, or there is no finite expiry: return
					// the stored token without calling the IdP, judging its type as on
					// the fast path.
					if (!mayDiscloseTokenType(freshTokens.tokenType)) {
						return refuseUndisclosableTokenType(ctx, caller, freshTokens.tokenType);
					}
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
						details: { federation, refreshed: false },
					});
					return res.status(200).json({
						access_token: freshTokens.accessToken,
						token_type: BEARER_TOKEN_TYPE,
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

			// The post-lock re-read may lack a refresh token too (a concurrent
			// revoke, or a rotation without one): 410 gives a precise re-auth
			// signal instead of an opaque upstream failure.
			if (!currentTokens.refreshToken) {
				return res.status(410).json({
					error: "refresh_token_absent",
					error_description: "no refresh token available for this federation (post-lock re-read)",
				});
			}

			// 11e: refresh with the freshest snapshot. The lock is held across the
			// IdP call; its TTL should cover the IdP timeout, else a second waiter
			// also calls the IdP — harmless, since `update` is atomic and the last
			// write wins.
			let refreshed: Awaited<ReturnType<typeof provider.refreshToken>>;
			try {
				refreshed = await provider.refreshToken(currentTokens.refreshToken);
			} catch (error) {
				// Awaited inside the `try`, so the lock is released after the answer.
				return await answerRefreshFailure(ctx, caller, error);
			}

			// Awaited inside the `try`, so the lock is released after the answer.
			return await recordRefresh(
				ctx,
				caller,
				currentTokens,
				readRefreshAnswer(refreshed, currentTokens),
			);
		} finally {
			// 11g: Release lock if acquired.
			if (release !== undefined) {
				try {
					await release();
				} catch (error) {
					logger.warn(
						{
							federation,
							store: "federation_token",
							step: "release_lock",
							err: loggableError(error),
						},
						"federation_token_lock_release_failed",
					);
				}
			}
		}
	});

	return router;
}
