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
	AccessTokenDenylist,
	AuditSink,
	ClientRepository,
	FederationProvider,
	FederationTokenStore,
	KeyStore,
	Logger,
	RefreshedTokens,
	RefreshTokenFamilyRevocation,
	SessionFederationIndex,
	SubjectRevocation,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	classifyFederationRefreshError,
	emitAuditEvent,
	supportsLock,
	supportsRefresh,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { parseAccessTokenHeader } from "../accessTokenHeader.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

/*
 * What a refresh answers is unverified until it is checked (D5). Every field
 * of `RefreshedTokens` is optional, and an adapter is a third-party extension
 * point: `@o3co/auth-provider-core` holds the same contract to the same bar in
 * `federation-grants/retrieve.mts`, and this route now reads the contract
 * rather than a local copy that declared the fields required (#626 P1).
 */

/** A credential the client could actually present: present, a string, not empty. */
const isNonEmptyString = (value: unknown): value is string =>
	typeof value === "string" && value !== "";

/** Alias at the call sites where the string is a token rather than a scope. */
const isUsableToken = isNonEmptyString;

/** Seconds a token has left: finite and in the future. `NaN` and `-5` are neither. */
const isUsableLifetime = (value: unknown): value is number =>
	typeof value === "number" && Number.isFinite(value) && value > 0;

/** A `Date` that names an instant. `new Date(NaN)` does not. */
const isUsableDate = (value: unknown): value is Date =>
	value instanceof Date && !Number.isNaN(value.getTime());

/**
 * What a refresh may record as the token's scope.
 *
 * RFC 6749 §6 lets a refresh narrow the granted scope and forbids it widening
 * one: "the scope of the access token … MUST NOT include any scope not
 * originally granted". An answer that adds a scope is therefore not a grant,
 * and recording it would leave the store claiming consent that was never
 * given. Absent, empty, or widening all keep what is stored. Mirrors
 * `scopesWithin` in `core/federation-grants/eligibility.mts`.
 */
const narrowedScope = (answered: unknown, stored: string | undefined): string | undefined => {
	if (!isNonEmptyString(answered)) return stored;
	if (!isNonEmptyString(stored)) return stored;
	const granted = new Set(stored.split(" ").filter((entry) => entry !== ""));
	const asked = answered.split(" ").filter((entry) => entry !== "");
	return asked.every((entry) => granted.has(entry)) ? answered : stored;
};

// `supportsRefresh` is core's, and so is the capability it narrows to: this
// route carried a structural copy of both while the contract lived in
// `@o3co/auth-provider-session`, which depends on core (#626 P1). It answers
// `false` for a missing provider, so a `Map.get()` result goes straight in.

export interface FederationTokenRouterOptions {
	keyStore: KeyStore;
	refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	userSessionStore: UserSessionStore;
	sessionFederationIndex: SessionFederationIndex;
	federationTokenStore: FederationTokenStore;
	clientRepository: ClientRepository;
	/** Wave 1 — RFC 7009: when wired, verifyJwt consults the denylist so revoked ATs respond 401. */
	accessTokenDenylist?: AccessTokenDenylist;
	/**
	 * #296 — when wired, verifyJwt rejects an access token whose `iat` is at or
	 * before this subject's revocation watermark. The subject-level companion to
	 * `accessTokenDenylist`: the denylist revokes a named token, this revokes
	 * every token a subject held as of a credential change.
	 */
	subjectRevocation?: SubjectRevocation;
	/**
	 * Getter for the federation providers Map. Evaluated at request time (not at
	 * router construction time) so module init order does not matter.
	 * Returns undefined when federation is not configured.
	 */
	getFederationProviders: () => ReadonlyMap<string, FederationProvider> | undefined;
	/** Audit sink for operator observability events. No-op when undefined. */
	auditSink?: AuditSink;
	/** Structured logger. Defaults to console when undefined. */
	logger?: Logger;
	/**
	 * Tokens within this many milliseconds of expiry are proactively refreshed.
	 * Default: 30_000 (30 seconds).
	 */
	refreshBufferMs?: number;
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

		// Step 1: Extract the access token from the Authorization header —
		// Bearer (RFC 6750 §2.1) or DPoP (RFC 9449 §7.1). Scheme-vs-`cnf`
		// agreement is enforced by `protectedResourceBindingMw` upstream.
		const token = parseAccessTokenHeader(req.headers.authorization);
		if (token === null) {
			res.setHeader(
				"WWW-Authenticate",
				'Bearer error="invalid_token", error_description="missing access token"',
			);
			return res
				.status(401)
				.json({ error: "invalid_token", error_description: "missing access token" });
		}

		// Step 2 + 3: SF-1 — alg / iss / typ (=at+jwt) + signature pinned by
		// the central verifier. Audience is deferred — bearer-as-credential
		// route, calling-client identity is not separately authenticated; the
		// verifier records the gap via `jwt_verify_aud_skipped`.
		// Wave 1 (C4): denylist consulted so revoked ATs respond 401 invalid_token.
		let payload: Record<string, unknown>;
		try {
			const verified = await verifyJwt(token, opts.keyStore, {
				type: "access_token",
				expectedIssuer: opts.issuer ?? "",
				legacyTypAccept: opts.legacyTypAccept ?? false,
				// #296/#367: token-accepting surface — forward what the composition
				// wired, jti denylist and subject watermark both.
				revocation: {
					denylist: opts.accessTokenDenylist,
					subjectRevocation: opts.subjectRevocation,
				},
				logger: opts.logger,
			});
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
			revoked = await opts.refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
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

		// A4 §6.2 Step 1: read federation index once for membership check + cleanup paths.
		let federations: ReadonlyArray<string>;
		try {
			federations = await opts.sessionFederationIndex.listFederations(sid);
		} catch (error) {
			logger.warn(
				`POST /oauth/federation/${name}/token: sessionFederationIndex.listFederations failed:`,
				error,
			);
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
			logger.warn(`POST /oauth/federation/${name}/token: clientRepository.findById failed:`, error);
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
				details: { federation: name, azp },
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
			// Self-heal: federation link is dangling — remove from federation index.
			try {
				await opts.sessionFederationIndex.removeFederation(sid, name);
			} catch (error) {
				logger.warn(
					`POST /oauth/federation/${name}/token: sessionFederationIndex.removeFederation self-heal failed:`,
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

			// SF-12 — post-lock RT guard.
			// The pre-lock guard (Step 11b above) catches the case where the very first
			// federationTokenStore.get returns a record without a refresh_token. The post-lock
			// re-read can ALSO produce such a record (e.g. concurrent revoke stripped the RT,
			// or the IdP rotated to a token set without an RT and the store recorded that).
			// Without this guard the IdP call would be made with `?? ""` — which the upstream
			// rejects opaquely and lands in 500 refresh_failed via the SF-13 fallback.
			// Returning 410 refresh_token_absent gives the caller a precise re-auth signal.
			if (!currentTokens.refreshToken) {
				return res.status(410).json({
					error: "refresh_token_absent",
					error_description: "no refresh token available for this federation (post-lock re-read)",
				});
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
			let refreshed: Awaited<ReturnType<typeof provider.refreshToken>>;
			try {
				// SF-12: `currentTokens.refreshToken` is narrowed to `string` by the guard
				// above. The pre-fix `?? ""` fallback is gone — the IdP cannot receive an
				// empty string under any branch.
				refreshed = await provider.refreshToken(currentTokens.refreshToken);
			} catch (error) {
				// SF-13: classify via structured properties first (openid-client v6 surfaces
				// `.error`, `.status`, `.code`), with message-string fallback for legacy /
				// non-openid-client errors. The fragile `msg.includes(...)` / `/5\d\d/.test(msg)`
				// path is now confined to the helper as last-resort.
				// SF-13's classifier lives in core now, shared with the federation grant
				// retrieval (#593). This route acts on the reason alone, the message
				// fallback included, exactly as before.
				const { reason } = classifyFederationRefreshError(error);
				logger.warn(
					`POST /oauth/federation/${name}/token: refreshToken failed (reason: ${reason}):`,
					error,
				);

				if (reason === "invalid_grant") {
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
						await opts.sessionFederationIndex.removeFederation(sid, name);
					} catch (cleanupErr) {
						logger.warn(
							`POST /oauth/federation/${name}/token: sessionFederationIndex.removeFederation cleanup failed:`,
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

				if (reason === "rate_limited") {
					return res.status(429).json({
						error: "rate_limited",
						error_description: "upstream IdP rate limit exceeded; retry later",
					});
				}

				if (reason === "network") {
					return res.status(503).json({
						error: "temporarily_unavailable",
						error_description: "upstream federation provider temporarily unavailable",
					});
				}

				// reason === "unknown" — generic 500 + audit with classifier reason for SIEM.
				emitAuditEvent(opts.auditSink, {
					timestamp: new Date(),
					type: "federation.token.refresh_failed",
					subject: sub ?? undefined,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: { federation: name, reason },
				});
				return res.status(500).json({
					error: "refresh_failed",
					error_description: "federation token refresh failed",
				});
			}

			// `RefreshedTokens.accessToken` is optional, and a refresh that produced
			// none is not a refresh: answering 200 without `access_token` would be
			// a malformed RFC 6749 §5.1 response, and writing `undefined` to the
			// store would lose the token still held. Treated as the refresh
			// failing, which is what it is. Reachable only since #626 P1 made this
			// route read the contract rather than a local copy that declared the
			// field required.
			//
			// An empty string is refused with it. An adapter is a third-party
			// extension point, so what it answers is unverified data until this
			// route checks it (D5) — the same bar `core/federation-grants/
			// retrieve.mts` holds the same contract to, too.
			//
			// `answer` rather than `refreshed`: an adapter may resolve with no
			// object at all, and reading a field off `null` would throw past the
			// refusal below, losing both the structured answer and the rotated
			// refresh token this branch exists to salvage.
			const answer: Partial<RefreshedTokens> =
				typeof refreshed === "object" && refreshed !== null ? refreshed : {};

			// A lifetime the upstream stated and got wrong is not the same as one
			// it never stated. `expiresAt: null` is stored as "no finite expiry",
			// which this route reads as never refresh again (the fast path above),
			// so letting `NaN`, a negative or zero lifetime, or an Invalid Date
			// fall through to it would leave an access token in indefinite use and
			// never checked. Core refuses the same readings —
			// `federation-grants/eligibility.mts`, `no_finite_lifetime`.
			const statedLifetime = answer.expiresIn !== undefined && answer.expiresIn !== null;
			const statedInstant = answer.expiresAt !== undefined && answer.expiresAt !== null;
			const lifetimeIsBroken =
				(statedLifetime && !isUsableLifetime(answer.expiresIn)) ||
				(statedInstant && !isUsableDate(answer.expiresAt));

			if (!isUsableToken(answer.accessToken) || lifetimeIsBroken) {
				// A rotated refresh token has to be kept even though the refresh
				// failed: the upstream invalidates the one it replaced (RFC 6749
				// §6), so discarding it here would leave the stored token dead and
				// the connection unrecoverable without re-consent. Best effort —
				// if the store is down the refresh is failing anyway.
				if (
					isUsableToken(answer.refreshToken) &&
					answer.refreshToken !== currentTokens.refreshToken
				) {
					try {
						await opts.federationTokenStore.update(sid, name, {
							...currentTokens,
							refreshToken: answer.refreshToken,
							// Rotated alongside it, and worth the same: the stored
							// `id_token` is what logout sends as `id_token_hint`.
							idToken: isUsableToken(answer.idToken) ? answer.idToken : currentTokens.idToken,
						});
					} catch (error) {
						logger.warn(
							`POST /oauth/federation/${name}/token: federationTokenStore.update failed while keeping a rotated refresh token:`,
							error,
						);
					}
				}
				emitAuditEvent(opts.auditSink, {
					timestamp: new Date(),
					type: "federation.token.refresh_failed",
					subject: sub ?? undefined,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: {
						federation: name,
						reason: lifetimeIsBroken ? "invalid_expiry" : "no_access_token",
					},
				});
				return res.status(500).json({
					error: "refresh_failed",
					error_description: "federation token refresh failed",
				});
			}

			// 11f: Update store — preserve refresh_token and id_token when IdP didn't rotate/return them.
			// Use currentTokens (post-lock re-read) as the fallback source so we never
			// revert to a stale pre-lock snapshot.
			// `RefreshedTokens.expiresAt` is optional as well as nullable, and the
			// two say different things: `null` is the provider committing to no
			// finite lifetime, `undefined` is the provider saying nothing about it.
			// A token's expiry comes from that token: the stored one belongs to the
			// token just replaced — expired, which is why this refresh ran — so
			// copying it forward would answer `expires_in: 0` and refresh again on
			// every request. Absent `expiresAt` falls back to the `expiresIn` the
			// same answer carried, and to `null` when it carries neither: a
			// lifetime nobody stated, which omits `expires_in` from the RFC 6749
			// §5.1 response. Until #626 P1 the local copy of the contract declared
			// the field required, so an answer without it threw on `.getTime()`.
			// Each reading is checked before it is believed: `NaN`, a negative
			// lifetime or an Invalid Date would be stored as an already-expired
			// expiry, and every later request would refresh again — the loop this
			// block exists to prevent, reached through the adapter instead of
			// through the store. An unusable reading falls through to the next
			// source, and to `null` when none of them is usable.
			const nextExpiresAt = isUsableDate(answer.expiresAt)
				? answer.expiresAt
				: answer.expiresAt === null
					? null
					: isUsableLifetime(answer.expiresIn)
						? new Date(Date.now() + answer.expiresIn * 1000)
						: null;
			const updatedTokens = {
				accessToken: answer.accessToken,
				// `??` would let `""` through, and an empty string overwriting a
				// usable stored token strands the connection at the next request.
				refreshToken: isUsableToken(answer.refreshToken)
					? answer.refreshToken
					: currentTokens.refreshToken,
				// IdPs like Google/GitHub typically don't return a new id_token on refresh.
				// Fall back to the stored id_token to preserve the id_token_hint for logout (F-5).
				idToken: isUsableToken(answer.idToken) ? answer.idToken : currentTokens.idToken,
				expiresAt: nextExpiresAt,
				// `token_type` stays the stored one: this route hands the client the
				// upstream's access token, and a change of type is a change of how
				// the client must present it. Honouring a rotated one is a decision
				// of its own, filed on #626, not a side effect of this move.
				tokenType: currentTokens.tokenType,
				// RFC 6749 §6: a refresh may NARROW the scope, and §5.1 makes the
				// answer authoritative when it differs. Storing the old one would
				// leave the record claiming access the upstream just withdrew.
				// Absent means unchanged, and widening is refused rather than
				// recorded: §6 forbids a refresh from granting a scope the user
				// never consented to, so an answer that adds one is the adapter
				// or the upstream misbehaving, not a grant.
				scope: narrowedScope(answer.scope, currentTokens.scope),
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
				nextExpiresAt === null
					? undefined
					: Math.max(0, Math.floor((nextExpiresAt.getTime() - Date.now()) / 1000));
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
				...(updatedTokens.scope ? { scope: updatedTokens.scope } : {}),
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
