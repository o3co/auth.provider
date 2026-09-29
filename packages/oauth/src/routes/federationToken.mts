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
	auditErrorText,
	BEARER_TOKEN_TYPE,
	canonicalScope,
	canonicalTokenType,
	classifyFederationRefreshError,
	emitAuditEvent,
	isBearerTokenType,
	isVerificationUnavailable,
	JwtVerificationError,
	logClientRepositoryUnavailable,
	loggableError,
	parseScopeTokens,
	sanitizeErrorText,
	supportsLock,
	supportsRefresh,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { parseAccessTokenHeader } from "../accessTokenHeader.mjs";
import { refuseVerificationUnavailable } from "../verificationUnavailable.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

/*
 * An adapter's refresh answer is unverified third-party data: every field of
 * `RefreshedTokens` is optional, and core holds the same contract to the same
 * bar in `federation-grants/retrieve.mts`.
 */

/** A credential the client could actually present: present, a string, not empty. */
const isNonEmptyString = (value: unknown): value is string =>
	typeof value === "string" && value !== "";

/** Alias at the call sites where the string is a token rather than a scope. */
const isUsableToken = isNonEmptyString;

/**
 * Seconds a caller is asked to wait before retrying a token this route may
 * not hand on — the default of `federationGrants.ineligibleRetryAfter` on the
 * offline-delegation route. A hint against a hot loop: the condition ends
 * only when the upstream's registration changes.
 */
const UPSTREAM_INELIGIBLE_RETRY_AFTER_SECONDS = 300;

/**
 * Whether a stored upstream token may be handed to the caller. This route
 * delegates the token by value to a caller holding no proof key, so only
 * `Bearer` qualifies: every other IANA access token type is sender-constrained
 * (`PoP`, `DPoP`) or not an access token (`N_A`), as core's
 * `federation-grants/eligibility.mts` also judges.
 *
 * Only an absent field is admitted unread (RFC 6749 §5.1 requires
 * `token_type`, so silence means an adapter or record that predates carrying
 * it). Anything present is read — `null`, `""` or a number included — so a
 * malformed record never answers `Bearer`.
 */
const mayDiscloseTokenType = (stored: unknown): boolean => {
	if (stored === undefined) return true;
	return isBearerTokenType(stored);
};

/** Seconds a token has left: finite and in the future. `NaN` and `-5` are neither. */
const isUsableLifetime = (value: unknown): value is number =>
	typeof value === "number" && Number.isFinite(value) && value > 0;

/**
 * One field of an adapter's answer, or `undefined` if its getter throws: an
 * exception would escape the structured refusal and lose the rotated refresh
 * token. `unreadable` records which, because for a lifetime field "absent"
 * means no finite expiry (never refresh), and a throwing getter must not
 * collapse into that.
 */
const readField = <T,>(source: object, key: string, unreadable: Set<string>): T | undefined => {
	try {
		return (source as Record<string, unknown>)[key] as T | undefined;
	} catch {
		unreadable.add(key);
		return undefined;
	}
};

/** A `Date` that names an instant. `new Date(NaN)` does not. */
const isUsableDate = (value: unknown): value is Date =>
	value instanceof Date && !Number.isNaN(value.getTime());

/**
 * How a refresh answer names the token's scope. `narrowedScope` bounds it by
 * `granted`, what the user consented to at link time: RFC 6749 §6 bounds a
 * refresh by the original grant, not by the token it replaces, so judging
 * against the current scope would make a narrowing permanent. A record
 * without `granted` is judged against its current scope.
 *
 * - narrower than the bound: recorded (§6 allows narrowing);
 * - named but unusable: the stored value stands — learning nothing is never
 *   a reason to widen;
 * - omitted: the bound itself — no `scope` is sent upstream, and §5.1 lets
 *   the answer omit it only when it matches the request, i.e. the grant;
 * - wider than the bound: not recorded; the stored value stands (§6).
 *
 * Reading silence as the bound can over-report after an upstream narrows,
 * but never beyond consent, and no authorization decision here reads the
 * field. Answers are canonical. The sibling rule for grants that outlive a
 * session is core's `scopesWithin` / `consentedScopes`.
 */
type AnsweredScope =
	/** The upstream named no scope at all. */
	| { readonly kind: "omitted" }
	/** It named one, and it parses. */
	| { readonly kind: "named"; readonly value: string }
	/** It named something this route could not use: unreadable, or not a scope. */
	| { readonly kind: "unusable" };

/**
 * Which reading an answer is. A getter that threw (`readField` → `undefined`)
 * is unusable, not omitted: omitted means the full grant, so collapsing the
 * two would let an adapter widen the scope by failing to be read.
 */
const classifyAnsweredScope = (
	answer: Partial<RefreshedTokens>,
	unreadable: ReadonlySet<string>,
): AnsweredScope => {
	if (unreadable.has("scope")) return { kind: "unusable" };
	if (answer.scope === undefined) return { kind: "omitted" };
	const named = parseScopeTokens(answer.scope);
	return named.length > 0 ? { kind: "named", value: named.join(" ") } : { kind: "unusable" };
};

const narrowedScope = (
	answered: AnsweredScope,
	stored: string | undefined,
	granted: string | undefined,
): string | undefined => {
	const storedValue = typeof stored === "string" ? stored : undefined;
	// The ceiling has to satisfy the same rule as the answer: a `granted` that
	// parses to nothing names no scope, whatever its characters, so it falls
	// through to the current scope rather than standing as an empty bound that
	// refuses everything forever.
	const bound = parseScopeTokens(granted);
	const allowed = bound.length > 0 ? bound : parseScopeTokens(stored);
	if (allowed.length === 0) return storedValue;
	// Canonical on every limb, including the ones that keep what is stored: a
	// record whose scope is ragged would otherwise keep that form forever, and
	// a whitespace-only one is truthy enough to be emitted in a 200.
	const keep = canonicalScope(stored);

	// Named but unusable is not silence. The upstream said something about the
	// scope and this route could not read it, so it learned nothing — and
	// nothing is a reason to keep what is stored, never to widen it.
	if (answered.kind === "unusable") return keep;
	if (answered.kind === "omitted") return allowed.join(" ");

	const asked = parseScopeTokens(answered.value);
	const within = new Set(allowed);
	return asked.every((entry) => within.has(entry)) ? asked.join(" ") : keep;
};

export interface FederationTokenRouterOptions {
	keyStore: KeyStore;
	refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	userSessionStore: UserSessionStore;
	sessionFederationIndex: SessionFederationIndex;
	federationTokenStore: FederationTokenStore;
	clientRepository: ClientRepository;
	/** RFC 7009: when wired, verifyJwt consults the denylist so revoked access tokens answer 401. */
	accessTokenDenylist?: AccessTokenDenylist;
	/**
	 * When wired, verifyJwt rejects an access token whose `iat` is at or before
	 * this subject's revocation watermark: the denylist revokes a named token,
	 * this revokes every token a subject held as of a credential change.
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
	/** Configured issuer, pinned by the central verifier. */
	issuer?: string;
	/**
	 * Accept tokens with no `typ` header, logging `jwt_verify_legacy_typ`.
	 * Default `false`; `true` is a legacy opt-in.
	 */
	legacyTypAccept?: boolean;
}

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
		// A store that cannot answer is `503`, logged once as
		// `federation_token_store_unavailable` with `store` and `step` and the
		// error's projection — never the error, which may quote a token record.
		const storeUnavailable = (
			federation: string,
			store: "user_session" | "session_federation_index" | "federation_token",
			step: "get" | "list" | "acquire_lock" | "get_after_lock" | "update",
			error: unknown,
		): void => {
			logger.error(
				{ federation, store, step, err: loggableError(error) },
				"federation_token_store_unavailable",
			);
		};
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

		// Steps 2 + 3: alg / iss / typ (at+jwt) and signature, pinned by the
		// verifier. Audience is not checked: the calling client is not
		// separately authenticated (logged as `jwt_verify_aud_skipped`).
		let payload: Record<string, unknown>;
		try {
			const verified = await verifyJwt(token, opts.keyStore, {
				type: "access_token",
				expectedIssuer: opts.issuer ?? "",
				legacyTypAccept: opts.legacyTypAccept ?? false,
				// A token-accepting surface: forward both the jti denylist and the
				// subject watermark.
				revocation: {
					denylist: opts.accessTokenDenylist,
					subjectRevocation: opts.subjectRevocation,
				},
				logger: opts.logger,
			});
			payload = verified.payload as Record<string, unknown>;
		} catch (error) {
			// The keystore or a revocation store did not answer: the server's
			// outage, not a verdict on the token (`isVerificationUnavailable`).
			if (isVerificationUnavailable(error)) {
				return refuseVerificationUnavailable(res, error, logger, "federation_token");
			}
			// Log the verifier's reason only: its message quotes token content,
			// and it has already logged `jwt_verify_rejected`.
			const verdict = error instanceof JwtVerificationError ? error.reason : undefined;
			logger.warn(
				verdict === undefined
					? { federation, err: loggableError(error) }
					: { federation, reason: verdict },
				"federation_token_jwt_verify_failed",
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

		/**
		 * Refuses a token whose type this route may not delegate. `502`: what
		 * came back from the upstream cannot be handed on, through no fault of
		 * the caller or this provider (the offline-delegation route answers the
		 * same). The named type goes to the audit sink, sanitised, not to the
		 * caller. `Retry-After` because the condition is not transient.
		 */
		const refuseUndisclosableTokenType = (res: Response, named: unknown): Response => {
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "federation.token.upstream_ineligible",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: {
					federation,
					reason: "token_type_unsupported",
					tokenType: typeof named === "string" ? auditErrorText(named) : null,
				},
			});
			res.setHeader("Retry-After", String(UPSTREAM_INELIGIBLE_RETRY_AFTER_SECONDS));
			return res.status(502).json({
				error: "upstream_token_ineligible",
				error_description: "token_type_unsupported",
			});
		};

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

		// Step 9: Get federation tokens. Throw → 503. null → self-heal + 404.
		let tokens: Awaited<ReturnType<typeof opts.federationTokenStore.get>>;
		try {
			tokens = await opts.federationTokenStore.get(sid, name);
		} catch (error) {
			storeUnavailable(federation, "federation_token", "get", error);
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
					{
						federation,
						store: "session_federation_index",
						step: "remove",
						err: loggableError(error),
					},
					"federation_token_index_self_heal_failed",
				);
				// Best-effort: still return 404 regardless
			}
			return res.status(404).json({
				error: "federation_not_linked",
				error_description: sanitizeErrorText(`federation '${name}' tokens not found`),
			});
		}

		// Step 10: not expiring within the buffer → return the stored token.
		// `expiresAt === null` is an upstream issuing no finite expiry (e.g.
		// GitHub OAuth App tokens): never refresh, and omit `expires_in`.
		if (tokens.expiresAt === null || tokens.expiresAt.getTime() > Date.now() + refreshBufferMs) {
			// The type is judged before the token is read and before the success
			// is audited, so a refused disclosure is not counted as one.
			if (!mayDiscloseTokenType(tokens.tokenType)) {
				return refuseUndisclosableTokenType(res, tokens.tokenType);
			}
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "federation.token.success",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { federation, refreshed: false },
			});
			const expiresIn =
				tokens.expiresAt === null
					? undefined
					: Math.max(0, Math.floor((tokens.expiresAt.getTime() - Date.now()) / 1000));
			return res.status(200).json({
				access_token: tokens.accessToken,
				token_type: BEARER_TOKEN_TYPE,
				...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
				...(tokens.scope ? { scope: tokens.scope } : {}),
			});
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
						return refuseUndisclosableTokenType(res, freshTokens.tokenType);
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
				// Core's classifier: an outage (unreachable, timeout, 5xx) is
				// `network`, a 429 is `rate_limited`, and `invalid_grant` is only
				// ever the upstream's structured verdict. Stored tokens are ended on
				// that verdict alone; an outage or rate limit keeps them for a retry.
				const classified = classifyFederationRefreshError(error);
				const { reason } = classified;
				// The projection, never the error: its cause chain can hold the
				// rotated refresh token. An unreachable upstream is this route's
				// outage (error); every other refusal is the upstream's (warn).
				if (reason === "network") {
					logger.error(
						{ federation, reason, err: loggableError(error) },
						"federation_token_upstream_unavailable",
					);
				} else {
					logger.warn(
						{ federation, reason, err: loggableError(error) },
						"federation_token_refresh_failed",
					);
				}

				if (reason === "invalid_grant") {
					// Cleanup: delete federation token + remove federation link.
					try {
						await opts.federationTokenStore.delete(sid, name);
					} catch (cleanupErr) {
						logger.warn(
							{
								federation,
								store: "federation_token",
								step: "delete",
								err: loggableError(cleanupErr),
							},
							"federation_token_cleanup_failed",
						);
					}
					try {
						await opts.sessionFederationIndex.removeFederation(sid, name);
					} catch (cleanupErr) {
						logger.warn(
							{
								federation,
								store: "session_federation_index",
								step: "remove",
								err: loggableError(cleanupErr),
							},
							"federation_token_cleanup_failed",
						);
					}
					emitAuditEvent(opts.auditSink, {
						timestamp: new Date(),
						type: "federation.token.reauthentication_required",
						subject: sub ?? undefined,
						ip: req.ip,
						userAgent: req.get("user-agent"),
						details: { federation },
					});
					return res.status(410).json({
						error: "re_authentication_required",
						error_description: "federation re-authentication required",
					});
				}

				if (reason === "rate_limited") {
					// The upstream's own wait, when it named one in whole seconds
					// (RFC 9110 §10.2.3); none is invented when it did not.
					if (classified.retryAfterSeconds !== undefined) {
						res.setHeader("Retry-After", String(classified.retryAfterSeconds));
					}
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
					details: { federation, reason },
				});
				return res.status(500).json({
					error: "refresh_failed",
					error_description: "federation token refresh failed",
				});
			}

			// The adapter's answer is unverified third-party data, read field by
			// field behind guards: it may be `null`, a getter may throw, and an
			// exception here would lose the rotated refresh token this branch
			// salvages. No (or an empty) access token is a failed refresh, never a
			// 200 without `access_token` (RFC 6749 §5.1).
			const unreadable = new Set<string>();
			const answer: Partial<RefreshedTokens> =
				typeof refreshed === "object" && refreshed !== null
					? {
							accessToken: readField<string>(refreshed, "accessToken", unreadable),
							refreshToken: readField<string>(refreshed, "refreshToken", unreadable),
							idToken: readField<string>(refreshed, "idToken", unreadable),
							expiresIn: readField<number | null>(refreshed, "expiresIn", unreadable),
							expiresAt: readField<Date | null>(refreshed, "expiresAt", unreadable),
							scope: readField<string>(refreshed, "scope", unreadable),
							tokenType: readField<string>(refreshed, "tokenType", unreadable),
						}
					: {};

			// A lifetime stated wrongly is not one never stated: `null` is stored
			// as "no finite expiry" (never refresh), so `NaN`, a non-positive
			// lifetime or an Invalid Date must not fall through to it (core's
			// `no_finite_lifetime` refuses the same).
			const statedLifetime = answer.expiresIn !== undefined && answer.expiresIn !== null;
			const statedInstant = answer.expiresAt !== undefined && answer.expiresAt !== null;

			// The instant the token expires at, derived here so the refusal below
			// can judge it. `null` is the upstream committing to no finite
			// lifetime; `undefined` on both fields is it saying nothing, which this
			// route has always stored as `null`.
			const derivedExpiry: Date | null = isUsableDate(answer.expiresAt)
				? answer.expiresAt
				: answer.expiresAt === null
					? null
					: isUsableLifetime(answer.expiresIn)
						? new Date(Date.now() + answer.expiresIn * 1000)
						: null;

			// The derived instant is judged too: a finite `expiresIn` can overflow
			// the Date range, and the Invalid Date stores as `null`. A lifetime in
			// one field denied by the other is self-contradictory, so neither is
			// believed.
			const contradictsItself =
				(answer.expiresAt === null && isUsableLifetime(answer.expiresIn)) ||
				(answer.expiresIn === null && isUsableDate(answer.expiresAt));

			const lifetimeIsBroken =
				// A lifetime field that would not be read is broken, not absent:
				// absent stores `null`, which is this route's never-refresh
				// sentinel, so the two must not collapse into one another.
				unreadable.has("expiresIn") ||
				unreadable.has("expiresAt") ||
				contradictsItself ||
				(statedLifetime && !isUsableLifetime(answer.expiresIn)) ||
				(statedInstant && !isUsableDate(answer.expiresAt)) ||
				((statedLifetime || statedInstant) &&
					derivedExpiry !== null &&
					!isUsableDate(derivedExpiry));

			// The refreshed token's type: unreadable or not a type name is broken
			// (joins the refusals below, as core's `retrieve.mts` does); absent
			// keeps the record's type, since a refresh does not change how tokens
			// are presented; a type name is what the record carries next.
			const namedType = answer.tokenType !== undefined;
			const answeredType = namedType ? canonicalTokenType(answer.tokenType) : undefined;
			const tokenTypeIsBroken =
				unreadable.has("tokenType") || (namedType && answeredType === undefined);
			// The stored value is carried verbatim: re-reading it through
			// `canonicalTokenType` would turn junk into absence, which reads as
			// Bearer. The disclosure check refuses it instead.
			const nextTokenType = answeredType ?? currentTokens.tokenType;

			/**
			 * Keeps a rotated refresh token even when this refresh brought
			 * nothing that can be handed on: the upstream invalidated the old one
			 * (RFC 6749 §6), so dropping it would strand the connection until
			 * re-consent. Best effort, logged as `federation_token_keep_rotated_*`;
			 * the route still answers its refusal, not a 503.
			 */
			const keepRotatedRefreshToken = async (): Promise<void> => {
				if (
					isUsableToken(answer.refreshToken) &&
					answer.refreshToken !== currentTokens.refreshToken
				) {
					let step: "get" | "update" = "get";
					try {
						// `currentTokens` may be stale (the lock TTL can lapse during the
						// upstream call), so re-read: if the stored refresh token changed,
						// another request rotated the chain and its record wins;
						// otherwise merge onto what is stored now.
						const latest = await opts.federationTokenStore.get(sid, name);
						if (latest === null) {
							// A concurrent logout unlinked this federation: writing would
							// restore credentials the user asked to drop.
							logger.warn(
								{ federation, store: "federation_token", reason: "record_gone" },
								"federation_token_keep_rotated_skipped",
							);
						} else if (latest.refreshToken !== currentTokens.refreshToken) {
							// Another request rotated the chain: its record is newer.
							logger.warn(
								{ federation, store: "federation_token", reason: "rotated_concurrently" },
								"federation_token_keep_rotated_skipped",
							);
						} else {
							step = "update";
							await opts.federationTokenStore.update(sid, name, {
								...latest,
								refreshToken: answer.refreshToken,
								// Rotated alongside it, and worth the same: the stored
								// `id_token` is what logout sends as `id_token_hint`.
								idToken: isUsableToken(answer.idToken) ? answer.idToken : latest.idToken,
							});
						}
					} catch (error) {
						logger.warn(
							{ federation, store: "federation_token", step, err: loggableError(error) },
							"federation_token_keep_rotated_failed",
						);
					}
				}
			};

			// The adapter answered something this route cannot read as a token.
			if (!isUsableToken(answer.accessToken) || lifetimeIsBroken || tokenTypeIsBroken) {
				await keepRotatedRefreshToken();
				emitAuditEvent(opts.auditSink, {
					timestamp: new Date(),
					type: "federation.token.refresh_failed",
					subject: sub ?? undefined,
					ip: req.ip,
					userAgent: req.get("user-agent"),
					details: {
						federation,
						reason: lifetimeIsBroken
							? "invalid_expiry"
							: !isUsableToken(answer.accessToken)
								? "no_access_token"
								: "invalid_token_type",
					},
				});
				return res.status(500).json({
					error: "refresh_failed",
					error_description: "federation token refresh failed",
				});
			}

			// The refresh worked but its token may not be handed on. Keep the
			// rotated refresh token so fixing the upstream needs no re-consent.
			if (!mayDiscloseTokenType(nextTokenType)) {
				await keepRotatedRefreshToken();
				return refuseUndisclosableTokenType(res, nextTokenType);
			}

			// 11f: store the refreshed tokens, falling back to the post-lock
			// snapshot for fields the IdP did not rotate. The expiry comes only
			// from this answer (`derivedExpiry`): the stored one belongs to the
			// expired token, and copying it forward would refresh on every
			// request. `null` omits `expires_in` (optional in RFC 6749 §5.1).
			const nextExpiresAt = derivedExpiry;
			const updatedTokens = {
				accessToken: answer.accessToken,
				// `??` would let `""` through, and an empty string overwriting a
				// usable stored token strands the connection at the next request.
				refreshToken: isUsableToken(answer.refreshToken)
					? answer.refreshToken
					: currentTokens.refreshToken,
				// IdPs like Google/GitHub typically return no new id_token on refresh;
				// keep the stored one, which logout sends as `id_token_hint`.
				idToken: isUsableToken(answer.idToken) ? answer.idToken : currentTokens.idToken,
				expiresAt: nextExpiresAt,
				// What the upstream last named, else what the record carried; judged
				// above, so the write and the response agree.
				tokenType: nextTokenType,
				// The three readings and the bound they are judged against are
				// `narrowedScope`'s, next to its own reasoning. Nothing about the
				// rule is restated here, so the two cannot drift apart.
				scope: narrowedScope(
					classifyAnsweredScope(answer, unreadable),
					currentTokens.scope,
					currentTokens.grantedScope,
				),
				// The ceiling itself never moves: a refresh is bounded by the grant,
				// not by the token it replaces (RFC 6749 §6). Parsed on the way back
				// out as well — it came from a store, and a store is another thing
				// this route does not own.
				grantedScope: canonicalScope(currentTokens.grantedScope),
			};
			try {
				await opts.federationTokenStore.update(sid, name, updatedTokens);
			} catch (error) {
				storeUnavailable(federation, "federation_token", "update", error);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "federation token store unavailable",
				});
			}

			// 11h: return the refreshed token; `expires_in` is omitted when there is
			// no finite expiry.
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
				details: { federation, refreshed: true },
			});
			return res.status(200).json({
				// `updatedTokens`, not the adapter's object: the answer was read once,
				// and a getter read a second time may answer differently from what was
				// just written to the store.
				access_token: updatedTokens.accessToken,
				token_type: BEARER_TOKEN_TYPE,
				...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
				...(updatedTokens.scope ? { scope: updatedTokens.scope } : {}),
			});
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
