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
	BEARER_TOKEN_TYPE,
	canonicalScope,
	canonicalTokenType,
	classifyFederationRefreshError,
	emitAuditEvent,
	isBearerTokenType,
	loggableError,
	parseScopeTokens,
	sanitizeErrorText,
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

/**
 * Seconds a caller is asked to wait before retrying a token this route may not
 * hand on. The same interval `federationGrants.ineligibleRetryAfter` defaults
 * to for the same condition on the offline-delegation route, which is where
 * the number comes from; this route has no setting of its own.
 *
 * It is a hint against a hot loop rather than a promise. Nothing is persisted
 * when the refusal happens on a refresh, so a caller that ignores it drives one
 * upstream call per request until an operator changes the upstream's
 * registration back — which is also the only thing that ends the condition.
 */
const UPSTREAM_INELIGIBLE_RETRY_AFTER_SECONDS = 300;

/**
 * Whether a stored upstream token may be handed to the caller (#645).
 *
 * The refusal is the same judgement core already makes of the same contract in
 * `federation-grants/eligibility.mts`, and for the same reason: every other
 * name in IANA's Access Token Types registry is either sender-constrained
 * (`PoP`, `DPoP`) or not an access token type at all (`N_A`), and this route
 * delegates the upstream's token BY VALUE to a caller that holds no proof key.
 * Answering such a token as `Bearer` — which is what this route did before —
 * drops a constraint the upstream imposed and hands out a credential that only
 * looks usable.
 *
 * Only an ABSENT field is admitted without being read. RFC 6749 §5.1 makes
 * `token_type` REQUIRED, so a record that names none was written from an
 * adapter that predates `FederationProfile` carrying it — a third-party one;
 * every bundled adapter names it through core's `federationTokenSnapshot` —
 * or linked before the bundled adapters did, rather than by an upstream
 * meaning something else. Every record written before #645 is silent too, and
 * this is what keeps them working.
 *
 * Everything else is READ, including a value that is not a token type at all.
 * A store is another thing this route does not own (D5), and the two must not
 * collapse: reading `"DPoP "`, `""` or a number as silence would answer
 * `Bearer` for it, which is the behaviour this issue exists to stop, reached
 * through a narrower door.
 *
 * `null` is one of those, not a second spelling of absence. Round-tripping a
 * record through JSON drops an `undefined` field rather than turning it into
 * `null`, so a stored `null` is a store writing one on purpose, and the
 * built-in Redis codec already refuses the record that holds it
 * (`isOptionalString`). Admitting it here would be the one reading that let a
 * malformed record answer 200.
 */
const mayDiscloseTokenType = (stored: unknown): boolean => {
	if (stored === undefined) return true;
	return isBearerTokenType(stored);
};

/** Seconds a token has left: finite and in the future. `NaN` and `-5` are neither. */
const isUsableLifetime = (value: unknown): value is number =>
	typeof value === "number" && Number.isFinite(value) && value > 0;

/**
 * One field of an adapter's answer, or `undefined` if it cannot be read.
 *
 * An adapter is a third-party extension point, so the answer may be an object
 * whose getters throw rather than a plain record. An exception raised while
 * reading it would escape the structured refusal and take the rotated refresh
 * token with it, so an unreadable field yields `undefined` here.
 *
 * `unreadable` is how the caller tells that apart from a field the adapter
 * simply did not set. The two must not be confused: on a lifetime field,
 * "absent" means the upstream stated nothing and the token is stored with no
 * finite expiry, which this route reads as never refresh again. Silently
 * turning a getter that throws into that sentinel would put the access token
 * into indefinite, unchecked use.
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
 * What a refresh may record as the token's scope.
 *
 * The bound is `granted`, what the user consented to when the federation was
 * linked, because RFC 6749 §6 bounds a refresh by the original grant and not
 * by the token it replaces. Judging against the current scope would make the
 * first narrowing permanent (#647). A record written before that field
 * existed has only its current scope to be judged against, which under-reports
 * rather than over-claims.
 *
 * Three readings of the answer:
 *
 * - **Narrower than the bound** — recorded. §6 lets a refresh narrow, and
 *   keeping the old value would leave the record claiming access the upstream
 *   has withdrawn.
 * - **Named but unusable** — the stored value stands. The upstream said
 *   something and this route could not read it, so it learned nothing, and
 *   nothing is never a reason to widen.
 * - **Nothing at all** — read as the bound itself. `SupportsRefresh.refreshToken`
 *   sends no `scope` upstream, so §6 makes the request one for the original
 *   grant, and §5.1 makes the answer's `scope` optional ONLY when it matches
 *   the request. A conforming upstream that has narrowed therefore has to say
 *   so every time; silence means the grant. Reading silence as "whatever the
 *   last narrowing left" is the permanent narrowing again, one door over.
 * - **Wider than the bound** — refused. §6 forbids a refresh granting a scope
 *   that was never consented to, so an answer that adds one is the upstream or
 *   the adapter misbehaving, not a grant.
 *
 * Everything is decided on the parsed lists and answered in canonical form, so
 * neither an upstream's spacing nor a repeated entry can become the value a
 * later refresh is judged against.
 *
 * **Which way this errs.** Reading silence as the bound can over-report: an
 * upstream that narrows and then says nothing on later refreshes leaves the
 * record claiming more than the token holds. That is deliberate, and it is the
 * opposite polarity from what this route used to choose. It is bounded by
 * consent — `grantedScope` is never exceeded and no authorization decision in
 * this provider reads the field, only the `scope` of the 200 does — so the
 * cost is a client told its token can do something it cannot, against the
 * alternative of a narrowing that could never be undone. A client that reads
 * the field to decide whether to re-prompt for consent is the case to watch.
 *
 * The bound itself is only ever narrowed by consent, never by an answer.
 *
 * The sibling of this rule for grants that outlive a session is
 * `scopesWithin` / `consentedScopes` in
 * `@o3co/auth-provider-core`'s `federation-grants/eligibility.mts`.
 */
type AnsweredScope =
	/** The upstream named no scope at all. */
	| { readonly kind: "omitted" }
	/** It named one, and it parses. */
	| { readonly kind: "named"; readonly value: string }
	/** It named something this route could not use: unreadable, or not a scope. */
	| { readonly kind: "unusable" };

/**
 * Which of the three readings an answer is.
 *
 * `undefined` reaches here for two different reasons and they must not be
 * confused — the same distinction the lifetime fields needed. `readField`
 * answers `undefined` when a getter throws, and silence means the original
 * grant, so collapsing the two would let an adapter widen the recorded scope
 * by failing to be read.
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
			logger.warn(`POST /oauth/federation/${name}/token: jwtVerify failed:`, loggableError(error));
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
		 * Refuse to hand on a token whose type this route may not delegate (#645).
		 *
		 * 502 rather than 500: this provider reached the upstream and what came
		 * back cannot be handed on — the caller did nothing wrong, and neither
		 * did this provider. `federation-grants/serialize.mts` answers the same
		 * code, with the same `error` and the same reason word, for the same
		 * condition on the offline-delegation route.
		 *
		 * The type the record named goes to the audit sink and not to the caller:
		 * an operator needs to know which upstream started answering something
		 * else, and the caller can do nothing with it but retry. It is reported
		 * as it was read, because a value that is not a token type is the thing
		 * worth seeing; `null` is a value that is not a string at all, which
		 * cannot be put in a field typed as one.
		 *
		 * `Retry-After` because the condition is not transient and a client that
		 * retries a 5xx otherwise drives one upstream refresh per retry — the
		 * offline-delegation route carries it on this same refusal for this same
		 * reason.
		 */
		const refuseUndisclosableTokenType = (res: Response, named: unknown): Response => {
			emitAuditEvent(opts.auditSink, {
				timestamp: new Date(),
				type: "federation.token.upstream_ineligible",
				subject: sub ?? undefined,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: {
					federation: name,
					reason: "token_type_unsupported",
					tokenType: typeof named === "string" ? named : null,
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

		// Step 5: Check family revocation. Fail-closed: any throw → 401.
		let revoked: boolean;
		try {
			revoked = await opts.refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
		} catch (error) {
			logger.warn(
				`POST /oauth/federation/${name}/token: isFamilyRevoked failed (refresh store outage):`,
				loggableError(error),
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
			logger.warn(
				`POST /oauth/federation/${name}/token: userSessionStore.get failed:`,
				loggableError(error),
			);
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
				loggableError(error),
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
			logger.warn(
				`POST /oauth/federation/${name}/token: clientRepository.findById failed:`,
				loggableError(error),
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
				error_description: sanitizeErrorText(`federation '${name}' is not linked to this session`),
			});
		}

		// Step 9: Get federation tokens. Throw → 503. null → self-heal + 404.
		let tokens: Awaited<ReturnType<typeof opts.federationTokenStore.get>>;
		try {
			tokens = await opts.federationTokenStore.get(sid, name);
		} catch (error) {
			logger.warn(
				`POST /oauth/federation/${name}/token: federationTokenStore.get failed:`,
				loggableError(error),
			);
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
					loggableError(error),
				);
				// Best-effort: still return 404 regardless
			}
			return res.status(404).json({
				error: "federation_not_linked",
				error_description: sanitizeErrorText(`federation '${name}' tokens not found`),
			});
		}

		// Step 10: If not expired (within buffer), return existing token.
		// `expiresAt === null` means the upstream provider issues no finite expiry
		// (e.g. GitHub OAuth Apps classic tokens). Treat as "never expired; never
		// refresh" — reuse the stored accessToken indefinitely, and omit the
		// `expires_in` field from the response (RFC 6749 §5.1 makes it optional).
		if (tokens.expiresAt === null || tokens.expiresAt.getTime() > Date.now() + refreshBufferMs) {
			// What it is presented as decides whether it may be handed on at all,
			// so it is read before the token is — and before the success is
			// audited, so a refused disclosure is not counted as one (#645).
			if (!mayDiscloseTokenType(tokens.tokenType)) {
				return refuseUndisclosableTokenType(res, tokens.tokenType);
			}
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
				token_type: BEARER_TOKEN_TYPE,
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
				logger.warn(
					`POST /oauth/federation/${name}/token: acquireLock failed:`,
					loggableError(error),
				);
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
						loggableError(error),
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
					// As on the fast path: the concurrent refresh that wrote this
					// record is not this request, so its type is judged here too.
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
						details: { federation: name, refreshed: false },
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
				// The projection, never the error: the adapter's library puts the
				// refresh answer it refused on the error's cause chain, and that
				// answer holds the rotated refresh token.
				logger.warn(
					`POST /oauth/federation/${name}/token: refreshToken failed (reason: ${reason}):`,
					loggableError(error),
				);

				if (reason === "invalid_grant") {
					// Cleanup: delete federation token + remove federation link.
					try {
						await opts.federationTokenStore.delete(sid, name);
					} catch (cleanupErr) {
						logger.warn(
							`POST /oauth/federation/${name}/token: federationTokenStore.delete cleanup failed:`,
							loggableError(cleanupErr),
						);
					}
					try {
						await opts.sessionFederationIndex.removeFederation(sid, name);
					} catch (cleanupErr) {
						logger.warn(
							`POST /oauth/federation/${name}/token: sessionFederationIndex.removeFederation cleanup failed:`,
							loggableError(cleanupErr),
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
			//
			// Each field is read once and behind a guard, because an object is not
			// the same as a readable one: a getter may throw, and an exception
			// escaping here costs the same salvage that a `null` answer would.
			// `core/federation-grants/retrieve.mts` guards the same contract the
			// same way, and reading field by field keeps a rotated `refreshToken`
			// usable even when a different getter is the one that throws.
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

			// A lifetime the upstream stated and got wrong is not the same as one
			// it never stated. `expiresAt: null` is stored as "no finite expiry",
			// which this route reads as never refresh again (the fast path above),
			// so letting `NaN`, a negative or zero lifetime, or an Invalid Date
			// fall through to it would leave an access token in indefinite use and
			// never checked. Core refuses the same readings —
			// `federation-grants/eligibility.mts`, `no_finite_lifetime`.
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

			// The DERIVED instant is what gets judged, not only the reading it came
			// from: a finite, positive `expiresIn` can still overflow the Date range
			// (`1e13` seconds puts it past the 8.64e15 ms maximum), and the Invalid
			// Date that results serialises to `null` in the store — the "never
			// expires" sentinel again, by a different route.
			// One field naming a lifetime while the other denies there is one is
			// the adapter contradicting itself, and the precedence below would
			// quietly resolve it toward `null` — the never-refresh sentinel. There
			// is no reading of the contract that makes both true, so neither is
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

			// How the refreshed token is to be presented (#645). Three readings,
			// and they are three different things:
			//
			// - Unreadable, or a value that is not a type name at all (`""`, one
			//   with a space in it, a number): the adapter answered something
			//   broken, which joins the refusals below. `core/federation-grants/
			//   retrieve.mts` drops the whole token on the same readings.
			// - Absent: the answer said nothing about the type, which leaves the
			//   one the record already carries. A refresh is not where a
			//   connection changes how its tokens are presented. Every bundled
			//   adapter names one; a third-party adapter may not.
			// - A type name: it is what the record will carry, and what decides
			//   whether the token may be handed on.
			const namedType = answer.tokenType !== undefined;
			const answeredType = namedType ? canonicalTokenType(answer.tokenType) : undefined;
			const tokenTypeIsBroken =
				unreadable.has("tokenType") || (namedType && answeredType === undefined);
			// The stored value is carried verbatim, not re-read through
			// `canonicalTokenType`: that would turn a stored value which is not a
			// token type into `undefined`, and the disclosure check reads absence
			// as Bearer. The record keeps what it holds, and the check below is
			// what refuses it.
			const nextTokenType = answeredType ?? currentTokens.tokenType;

			/**
			 * Keep a rotated refresh token even though this refresh brought
			 * nothing that can be handed on.
			 *
			 * A rotated refresh token has to be kept: the upstream invalidates the
			 * one it replaced (RFC 6749 §6), so discarding it here would leave the
			 * stored token dead and the connection unrecoverable without
			 * re-consent. Best effort — if the store is down the refresh is
			 * failing anyway.
			 *
			 * Shared by both refusals below, which differ in what they answer and
			 * not in what they owe the connection (#645).
			 */
			const keepRotatedRefreshToken = async (): Promise<void> => {
				if (
					isUsableToken(answer.refreshToken) &&
					answer.refreshToken !== currentTokens.refreshToken
				) {
					try {
						// `currentTokens` may be stale by now. The lock TTL can
						// expire during the upstream call — this route says so, and
						// allows another request to acquire the lock and refresh —
						// so writing the pre-call snapshot back would overwrite a
						// concurrent success with an expired access token.
						//
						// Re-read, and let the record decide. A stored refresh token
						// that is no longer the one sent upstream means another
						// request already rotated the chain: its record is both newer
						// and complete, so the rotated token here is not worth a
						// write. Otherwise merge onto what is stored now rather than
						// onto what was read before the call.
						const latest = await opts.federationTokenStore.get(sid, name);
						if (latest === null) {
							// The record is gone — a concurrent logout unlinked this
							// federation. Writing here would put credentials back
							// after the user asked for them to be dropped, which is
							// worse than losing a rotated token on a refresh that
							// already failed.
							logger.warn(
								`POST /oauth/federation/${name}/token: the federation token record is gone; not recreating it with the failed refresh's token`,
							);
						} else if (latest.refreshToken !== currentTokens.refreshToken) {
							logger.warn(
								`POST /oauth/federation/${name}/token: a concurrent refresh rotated this connection; not overwriting it with the failed refresh's token`,
							);
						} else {
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
							`POST /oauth/federation/${name}/token: federationTokenStore.update failed while keeping a rotated refresh token:`,
							loggableError(error),
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
						federation: name,
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

			// The adapter answered a token this route may not hand on (#645). Not
			// a failed refresh — the refresh worked, and the token it brought is
			// one the caller could not present. Keeping the rotated refresh token
			// matters more here than on a failure: the connection is healthy, and
			// an operator who fixes the upstream's configuration must not have to
			// send the user back for consent.
			if (!mayDiscloseTokenType(nextTokenType)) {
				await keepRotatedRefreshToken();
				return refuseUndisclosableTokenType(res, nextTokenType);
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
			const nextExpiresAt = derivedExpiry;
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
				// What the upstream last named, or what the record already carried
				// when this answer named nothing. Judged above before it got here:
				// the write and the response say the same thing because they read
				// the same value (#645).
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
				logger.warn(
					`POST /oauth/federation/${name}/token: federationTokenStore.update failed:`,
					loggableError(error),
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
						`POST /oauth/federation/${name}/token: lock release failed:`,
						loggableError(error),
					);
				}
			}
		}
	});

	return router;
}
