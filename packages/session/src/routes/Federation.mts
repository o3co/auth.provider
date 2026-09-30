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

/**
 * The federation routes. `GET /oauth/federation/:name` starts a federation
 * (state, PKCE, nonce; for `form_post`, a transaction record and its cookie).
 * The callback — `GET` for a `query` federation, `POST` for `form_post` —
 * checks the envelope, exchanges the code, resolves the identity through
 * `UserRepository`, then either links it to the live session (`?link=1`) or
 * establishes a session via `establishSession`, from an establishment core
 * builds without asking the requirements (`establishWithoutAsking`), and
 * redirects per the federation's redirect policy. The link flow reads its
 * session through admission: `session.link` at the start, and
 * `session.link_callback` over the `sid` and subject the start recorded.
 */

import { randomBytes } from "node:crypto";
import {
	type Admission,
	type AppConfig,
	type AuditSink,
	admitSession,
	auditErrorText,
	checkResolver,
	consoleLogger,
	cookieClaim,
	emitAuditEvent,
	errorEnvelope,
	establishWithoutAsking,
	type FederationProvider,
	type FederationTokenStore,
	federationTrustsUpstreamAmr,
	type Logger,
	linkClaim,
	loggableError,
	resolveFederationResponseMode,
	type SessionClaim,
	type SessionFederationIndex,
	type SessionRequirementResolver,
	type SubjectRevocation,
	type SubjectSessionIndex,
	sanitizeErrorText,
	supportsClaimMapping,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { SESSION_ADMISSION_ACTIONS, type SessionAdmissionAction } from "../admissionActions.mjs";
import { checkNavigationOrigin } from "../csrf.mjs";
import { type EstablishSessionStep, establishSession } from "../establish-session.mjs";
import { mergeFederatedClaims } from "../federations/claim-precedence.mjs";
import { consentedScope } from "../federations/consented-scope.mjs";
import { generateCodeVerifier } from "../federations/pkce.mjs";
import type { FederationRedirectPolicy } from "../federations/redirect-policy.mjs";
import {
	createFederationTransactionStore,
	DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
	deriveFederationTransactionCookieName,
	type FederationTransactionEnvelope,
	type FederationTransactionSessionStore,
	type FederationTransactionStore,
	type LinkIntent,
	mintFederationTransactionId,
} from "../federations/transaction.mjs";
import {
	abandonCookieSession,
	admissionUnavailable,
	SESSION_STORE_UNAVAILABLE,
	USER_DIRECTORY_UNAVAILABLE,
} from "../internal/cookieSession.mjs";
import { readCookie } from "../internal/cookies.mjs";
import { extractUserClaims } from "../internal/extractUserClaims.mjs";
import { loginRequestFacts } from "../internal/loginRequest.mjs";
import { refusalEnvelope } from "../internal/refusalEnvelope.mjs";

declare module "express-session" {
	interface SessionData {
		/** Ephemeral state for a `"query"` federation's redirect leg, deleted by
		 *  the callback right after the state check (reuse prevention). A
		 *  `"form_post"` federation keeps it in a transaction record instead: its
		 *  cross-site POST callback does not carry the session cookie. */
		federation?: {
			name: string;
			state: string;
			codeVerifier: string;
			/** Bound to the upstream id_token via openid-client `expectedNonce`;
			 *  optional so OAuth-only providers can omit it. */
			nonce?: string;
			redirectTo?: string;
			/** A `?link=1` start: link this federation's identity to the account
			 *  of the session it came from (its `sid` and the subject admission
			 *  allowed), rather than log in. */
			link?: LinkIntent;
		};
	}
}

const DEFAULT_SESSION_TTL_MS = 86_400_000; // 24 h

/** The link routes ask admission for no `acr_values`: the table it selects against is empty. */
const NO_ACR_TABLE = Object.freeze({});

/**
 * The link start's answer to a step-up: `403 step_up_required` with the
 * requirement and its registered page. The start is a browser navigation, so
 * the page it came from can send the user through the step-up and start
 * again; no return parameter is added, since that page knows where it
 * returns to.
 */
const stepUpRequired = (admission: Extract<Admission, { outcome: "step_up" }>) => ({
	error: "step_up_required",
	error_description: "Linking a federated identity requires a step-up first",
	requirement: admission.requirement,
	page: admission.page.href,
});

/**
 * The upstream IdP's own `amr` (when the provider surfaces the id_token's as
 * a string array), else nothing. Whether it counts is the federation's
 * `trustUpstreamAmr`: core records it beside `fed` for a trusted federation
 * and apart from the session's `amr` otherwise.
 */
const upstreamAmrOf = (profile: Readonly<Record<string, unknown>>): readonly string[] =>
	Array.isArray(profile.amr) && profile.amr.every((v) => typeof v === "string")
		? (profile.amr as string[])
		: [];

/**
 * The record's `tokenType` for what an adapter answered: the upstream's
 * spelling verbatim, even when it is not a token type, because the
 * disclosing route reads only an absent field as `Bearer` — erasing an
 * unusable value would turn a refusal into a 200. A non-string is recorded
 * as `""`, which that route also refuses.
 */
const recordedTokenType = (named: unknown): string | undefined => {
	if (named === undefined) return undefined;
	return typeof named === "string" ? named : "";
};

/**
 * The session cookie name assumed when neither
 * `federationTransactionCookieName` nor `config.session.name` is given (a
 * hand-built config only): `reference.conf`'s default without `__Host-`.
 */
const FALLBACK_SESSION_COOKIE_NAME = "auth.session";

/** Read `config.session.name` without assuming the caller supplied a full AppConfig. */
const readSessionCookieName = (config: unknown): string => {
	if (config == null || typeof config !== "object") return FALLBACK_SESSION_COOKIE_NAME;
	const session = (config as { session?: unknown }).session;
	if (session == null || typeof session !== "object") return FALLBACK_SESSION_COOKIE_NAME;
	const name = (session as { name?: unknown }).name;
	return typeof name === "string" && name.length > 0 ? name : FALLBACK_SESSION_COOKIE_NAME;
};

/** Read `config.session.csrf.trustedOrigins` without assuming a full AppConfig. */
const readCsrfTrustedOrigins = (config: unknown): readonly string[] => {
	const csrf = (config as { session?: { csrf?: { trustedOrigins?: unknown } } } | null | undefined)
		?.session?.csrf;
	const list = csrf?.trustedOrigins;
	return Array.isArray(list) ? list.filter((o): o is string => typeof o === "string") : [];
};

/**
 * Narrow a callback's parameter bag (`req.query` or `req.body`) to its string
 * entries. Both are attacker-shapeable (repeats arrive as arrays, bodies can
 * nest), so `state` is only ever compared with a string or `undefined`, and
 * adapters get flat strings.
 */
const readCallbackParams = (source: unknown): Readonly<Record<string, string>> => {
	if (source == null || typeof source !== "object") return {};
	return Object.fromEntries(
		Object.entries(source as Record<string, unknown>).filter(
			(entry): entry is [string, string] => typeof entry[1] === "string",
		),
	);
};

/**
 * The stores the federation routes read or write, as their log lines name
 * them. `cookie_session` is the express-session store behind `req.session`;
 * `federation_transaction` is a `form_post` federation's transaction record,
 * kept in that same store under a key of its own.
 */
type FederationStore =
	| "user_repository"
	| "user_session"
	| "session_federation_index"
	| "federation_token"
	| "subject_session_index"
	| "federation_transaction"
	| "cookie_session";

/** The operation on a {@link FederationStore} that failed, as a log line names it. */
type FederationStoreStep =
	| "get"
	| "set"
	| "delete"
	| "save"
	| "regenerate"
	| "destroy"
	| "create"
	| "authenticate_by_token"
	| "link"
	| "list"
	| "add"
	| "attach"
	| "remove"
	| "remove_by_sid"
	| "remove_sid";

/** Which leg of a federation a store outage stopped. */
type FederationOutageEvent =
	| "federation_start_store_unavailable"
	| "federation_callback_store_unavailable"
	| "federation_link_store_unavailable";

/**
 * A store a federation route cannot do without could not answer: the
 * server's outage, never a verdict on the user or the IdP. One error line
 * named for the leg, with `store`, `step` and the error's projection — never
 * the error, which can carry a token record. The caller answers `503`.
 */
const logStoreUnavailable = (
	log: Logger,
	event: FederationOutageEvent,
	store: FederationStore,
	step: FederationStoreStep,
	cause: unknown,
	context: Readonly<Record<string, unknown>> = {},
): void => {
	log.error({ ...context, store, step, err: loggableError(cause) }, event);
};

/** A composition fault a federation route can meet, as its log line names it. */
type FederationMisconfiguration =
	| "no_callback_url"
	| "no_redirect_policy"
	| "no_session_store"
	| "no_callback_path";

/**
 * A federation route met a composition fault — a provider with no callback URL
 * or no redirect policy, a `form_post` federation with no express-session
 * store on its requests or a callback URL with no path to scope its cookie
 * to. No client causes it and no retry fixes it: one line at error level,
 * `federation_misconfigured`, with the `reason`; the caller answers `500`.
 */
const logMisconfigured = (
	log: Logger,
	reason: FederationMisconfiguration,
	context: Readonly<Record<string, unknown>> = {},
): void => {
	log.error({ ...context, reason }, "federation_misconfigured");
};

/**
 * The warn line a best-effort step that failed is logged as,
 * `federation_cleanup_failed`: `store`, `step` and the error's projection.
 * {@link cleanUp} emits it for the steps this router runs itself; the login
 * tail's reporter emits it for the ones `establishSession` runs.
 */
const logCleanupFailed = (
	log: Logger,
	store: FederationStore,
	step: FederationStoreStep,
	cause: unknown,
	context: Readonly<Record<string, unknown>> = {},
): void => {
	log.warn({ ...context, store, step, err: loggableError(cause) }, "federation_cleanup_failed");
};

/**
 * Run one best-effort cleanup step — a rollback after a failed link, the
 * discard of a refused transaction. A step that fails is one
 * {@link logCleanupFailed} line; the request's own answer stands either way.
 */
const cleanUp = async (
	log: Logger,
	store: FederationStore,
	step: FederationStoreStep,
	run: () => Promise<unknown>,
	context: Readonly<Record<string, unknown>> = {},
): Promise<void> => {
	try {
		await run();
	} catch (err) {
		logCleanupFailed(log, store, step, err, context);
	}
};

export const createRouter = (
	express: {
		Router: () => Router;
		json: () => RequestHandler;
		urlencoded: (opts: { extended: boolean }) => RequestHandler;
	},
	{
		config,
		federationProviders,
		federationRedirectPolicyResolver,
		providerCallbackUrls,
		userRepository,
		userSessionStore,
		subjectSessionIndex,
		subjectRevocation,
		sessionFederationIndex,
		federationTokenStore,
		sessionTtlMs = DEFAULT_SESSION_TTL_MS,
		federationTransactionTtlMs = DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
		federationTransactionCookieName,
		requirements,
		auditSink,
		logger = consoleLogger,
	}: {
		config: AppConfig;
		federationProviders: ReadonlyMap<string, FederationProvider>;
		federationRedirectPolicyResolver: ReadonlyMap<string, FederationRedirectPolicy>;
		providerCallbackUrls: ReadonlyMap<string, string>;
		userRepository: UserRepository;
		userSessionStore: UserSessionStore;
		/**
		 * Subject-keyed index of live sessions. Optional: without it there is no
		 * subject-level revocation, which `revokeAllForSubject` reports.
		 */
		subjectSessionIndex?: SubjectSessionIndex;
		/**
		 * The subject-revocation boundary the link flow's admission reads.
		 * Optional: without it a session established before its subject's
		 * sessions were revoked can link until it expires.
		 */
		subjectRevocation?: SubjectRevocation;
		sessionFederationIndex: SessionFederationIndex;
		federationTokenStore: FederationTokenStore;
		sessionTtlMs?: number;
		/**
		 * How long a `form_post` federation's transaction may sit unconsumed;
		 * bounds the cookie's `Max-Age` and the record's expiry together.
		 */
		federationTransactionTtlMs?: number;
		/**
		 * Name of the `form_post` transaction cookie. Defaults to the
		 * deployment's session cookie name run through
		 * {@link deriveFederationTransactionCookieName}, so it inherits the
		 * operator's naming without inheriting a `__Host-` prefix this
		 * path-scoped cookie could not satisfy.
		 */
		federationTransactionCookieName?: string;
		/**
		 * The registered session requirements the link routes admit through.
		 * Required: a missing resolver, or one the boot planner did not build,
		 * is refused at construction.
		 */
		requirements: SessionRequirementResolver;
		/**
		 * Receives `federation.identity.linked` / `federation.identity.link_refused`
		 * and admission's `session.admission.subject_mismatch`. Optional.
		 */
		auditSink?: AuditSink;
		logger?: Logger;
	},
): Router => {
	checkResolver(requirements, "federation routes", Object.keys(SESSION_ADMISSION_ACTIONS));
	if (!userSessionStore) throw new Error("federation routes require userSessionStore");
	if (!sessionFederationIndex) throw new Error("federation routes require sessionFederationIndex");
	if (!federationTokenStore) throw new Error("federation routes require federationTokenStore");
	if (!userRepository) throw new Error("federation routes require userRepository");
	if (!providerCallbackUrls) throw new Error("federation routes require providerCallbackUrls");

	const router = express.Router();

	/**
	 * The link flow's one reading of a session: admission, with this router's
	 * slots. An outage is logged on `log`, once, by admission.
	 */
	const admitLink = (claim: SessionClaim, action: SessionAdmissionAction, log: Logger) =>
		admitSession(
			{
				userSessionStore,
				subjectRevocation,
				requirements,
				acrTable: NO_ACR_TABLE,
				logger: log,
				auditSink,
			},
			{ claim, action },
		);

	// Whether each installed federation's upstream `amr` counts, read once at
	// composition (an unusable switch refuses to build the routes) by the same
	// reading the `acr` table uses, so a session's record and `/authorize`'s
	// advertisement agree. Keyed by the installed name the callback resolves by.
	const trustsUpstreamAmr = new Map<string, boolean>(
		[...federationProviders.keys()].map((name) => [
			name,
			federationTrustsUpstreamAmr(config, name),
		]),
	);

	const transactionCookieName =
		federationTransactionCookieName ??
		deriveFederationTransactionCookieName(readSessionCookieName(config));
	const linkTrustedOrigins = readCsrfTrustedOrigins(config);

	/**
	 * The federation transaction store, over the express-session store the
	 * session middleware mounted (taken off the request, not injected, so it
	 * cannot point elsewhere). Absent means no session middleware — a
	 * composition error the `form_post` start refuses.
	 */
	const transactionStore = (req: Request): FederationTransactionStore | undefined => {
		const store = (req as unknown as { sessionStore?: unknown }).sessionStore;
		if (store == null || typeof store !== "object") return undefined;
		const candidate = store as Partial<FederationTransactionSessionStore>;
		if (
			typeof candidate.get !== "function" ||
			typeof candidate.set !== "function" ||
			typeof candidate.destroy !== "function"
		) {
			return undefined;
		}
		return createFederationTransactionStore(candidate as FederationTransactionSessionStore);
	};

	/**
	 * The path the transaction cookie is scoped to: the provider's callback
	 * route only. A `SameSite=None` cookie rides every cross-site request to a
	 * matching path, so the narrower the better.
	 */
	const transactionCookiePath = (provider: FederationProvider): string | undefined => {
		const callbackUrl = providerCallbackUrls.get(provider.name);
		if (!callbackUrl) return undefined;
		try {
			return new URL(callbackUrl).pathname;
		} catch {
			return undefined;
		}
	};

	/** Attributes shared by the `Set-Cookie` that issues the cookie and the one that clears it. */
	const transactionCookieAttributes = (path: string) =>
		({
			httpOnly: true,
			// `SameSite=None` is what makes the cookie reach a cross-site POST,
			// and every current browser drops such a cookie unless it is also
			// `Secure`. Apple refuses a non-`https` redirect URI anyway, so a
			// form_post federation is HTTPS-only regardless.
			secure: true,
			sameSite: "none",
			path,
		}) as const;

	/**
	 * Drop the transaction cookie. Called on every callback exit — success,
	 * refusal and error alike — so a consumed or unusable transaction never
	 * leaves a cookie behind for the next attempt to trip over.
	 */
	const clearTransactionCookie = (provider: FederationProvider, res: Response): void => {
		const path = transactionCookiePath(provider);
		if (path === undefined) return;
		res.clearCookie(transactionCookieName, transactionCookieAttributes(path));
	};

	/**
	 * Link a federated identity to the account the browser is signed in as,
	 * without minting a session. Reached only from an explicit `?link=1` start
	 * whose envelope was verified like a login's. An identity resolving to
	 * nobody asks the Store to link; to someone else is `409` (linking never
	 * merges accounts); to this account links nothing new. The federation is
	 * then attached to the live session (index entry and upstream tokens under
	 * the current `sid`); no `UserSession` is created and the session is not
	 * regenerated. The session is admitted as `session.link_callback`; a
	 * step-up is `login_required`, since the IdP's callback has no page to
	 * return to.
	 */
	const completeLink = async (
		provider: FederationProvider,
		profile: Awaited<ReturnType<FederationProvider["exchangeCode"]>>,
		identityToken: string,
		resolved: Awaited<ReturnType<typeof userRepository.authenticateByToken>>,
		redirectTo: string | undefined,
		link: LinkIntent,
		req: Request,
		res: Response,
		log: Logger,
	): Promise<unknown> => {
		// The link belongs to the session the start recorded, not whichever
		// session the browser holds now: a `form_post` callback arrives without
		// the session cookie (SameSite=Lax), so the recorded `sid` is the only
		// binding. A request that does carry an authenticated session must carry
		// that same one — switching accounts in between links nothing.
		const currentSid = link.sid;
		const cookie = cookieClaim(req);
		if (cookie.authenticated && cookie.sid !== currentSid) {
			return res.status(401).json({
				error: "login_required",
				error_description: "The link was started from a different session",
			});
		}
		const notLive = () =>
			res.status(401).json({
				error: "login_required",
				error_description: "Linking a federated identity requires a live session",
			});
		// A transaction recorded without a subject cannot form the link claim
		// (the sid and subject together): the user starts the link again.
		if (typeof link.subject !== "string" || link.subject.length === 0) return notLive();
		const admission = await admitLink(
			linkClaim({ sid: currentSid, subject: link.subject }),
			"session.link_callback",
			log,
		);
		if (admission.outcome === "unavailable") {
			return res.status(503).json(admissionUnavailable(admission.store));
		}
		// Not live, revoked, a requirement not met — or one asking for a
		// step-up, which the callback has no page to return to.
		if (admission.outcome !== "admitted" || admission.session === null) return notLive();
		const current = admission.session;
		// Every line the link writes names the session it was for.
		const linkContext = { sid: currentSid };
		// The three emissions below spell their `type` literally, which is what
		// the audit-inventory guard reads.
		const auditBase = () => ({
			timestamp: new Date(),
			subject: current.sub,
			ip: req.ip,
			userAgent: req.get("user-agent"),
		});

		if (resolved && resolved.id !== current.sub) {
			void emitAuditEvent(auditSink, {
				...auditBase(),
				type: "federation.identity.link_refused",
				details: { provider: provider.name, reason: "conflict" },
			});
			return res.status(409).json({
				error: "identity_conflict",
				error_description: "This federated identity is already linked to another account",
			});
		}
		if (!resolved) {
			if (typeof userRepository.linkFederatedIdentity !== "function") {
				return res.status(400).json({
					error: "link_unsupported",
					error_description: "The user repository does not support linking federated identities",
				});
			}
			const mapped = supportsClaimMapping(provider) ? provider.mapClaims(profile) : {};
			let outcome: Awaited<ReturnType<NonNullable<typeof userRepository.linkFederatedIdentity>>>;
			try {
				outcome = await userRepository.linkFederatedIdentity(current.sub, {
					provider: provider.name,
					sub: profile.sub,
					token: identityToken,
					claims: { ...(mapped as Record<string, unknown>) },
				});
			} catch (err) {
				logStoreUnavailable(
					log,
					"federation_link_store_unavailable",
					"user_repository",
					"link",
					err,
					linkContext,
				);
				return res.status(503).json(USER_DIRECTORY_UNAVAILABLE);
			}
			if (!outcome.ok) {
				void emitAuditEvent(auditSink, {
					...auditBase(),
					type: "federation.identity.link_refused",
					details: { provider: provider.name, reason: outcome.reason },
				});
				const conflict = outcome.reason === "conflict";
				return res.status(conflict ? 409 : 403).json({
					error: conflict ? "identity_conflict" : "link_refused",
					// The Store's own words when it gave any: an adapter's text, held to
					// RFC 6749's characters (Appendix A.8), with ours for one that is
					// absent, empty or not a string.
					error_description:
						sanitizeErrorText(outcome.description) ||
						(conflict
							? "This federated identity is already linked to another account"
							: "The user directory refused to link this identity"),
				});
			}
			void emitAuditEvent(auditSink, {
				...auditBase(),
				type: "federation.identity.linked",
				details: { provider: provider.name },
			});
		}

		// Whether the session already carried this federation: a failed re-link
		// must not take an existing attachment down with it. `listed` says the
		// read answered at all — until it has, nothing was written and there is
		// nothing this request may undo.
		let hadFederation = false;
		let listed = false;
		// The write in flight, so the one catch that answers them all can log
		// the one that failed.
		let linking: { store: FederationStore; step: FederationStoreStep } = {
			store: "session_federation_index",
			step: "list",
		};
		try {
			hadFederation = (await sessionFederationIndex.listFederations(currentSid)).includes(
				provider.name,
			);
			listed = true;
			linking = { store: "session_federation_index", step: "add" };
			await sessionFederationIndex.addFederation(currentSid, provider.name, current.expiresAt);
			if (profile.accessToken) {
				linking = { store: "federation_token", step: "attach" };
				const consented = consentedScope(profile.scope, provider.scope);
				const tokenType = recordedTokenType(profile.tokenType);
				await federationTokenStore.attach(currentSid, provider.name, {
					accessToken: profile.accessToken,
					refreshToken: profile.refreshToken,
					idToken: profile.idToken,
					expiresAt: profile.expiresAt,
					// The consented scope: `scope` moves with the token;
					// `grantedScope` is the ceiling a refresh is bounded by (RFC 6749
					// §6) and never moves. They start equal.
					scope: consented,
					grantedScope: consented,
					// Recorded, not judged: a login does not need the access token,
					// so a type this provider cannot hand on must not cost the
					// sign-in; the disclosing route decides. Always written as a key,
					// since `FederationTokens` requires it.
					tokenType,
				});
			}
		} catch (err) {
			logStoreUnavailable(
				log,
				"federation_link_store_unavailable",
				linking.store,
				linking.step,
				err,
				linkContext,
			);
			// Best-effort rollback. The Store's link stands (the identity is the
			// account's), but a half-attached federation must not be left on the
			// live session: token record first, then index entry — unless the
			// session already carried the federation, or the index could not even
			// be read (then nothing was written).
			if (listed && !hadFederation) {
				await cleanUp(
					log,
					"federation_token",
					"delete",
					() => federationTokenStore.delete(currentSid, provider.name),
					linkContext,
				);
				await cleanUp(
					log,
					"session_federation_index",
					"remove",
					() => sessionFederationIndex.removeFederation(currentSid, provider.name),
					linkContext,
				);
			}
			return res.status(503).json(SESSION_STORE_UNAVAILABLE);
		}
		const policy = federationRedirectPolicyResolver.get(provider.name);
		if (!policy) {
			logMisconfigured(log, "no_redirect_policy");
			return res.status(500).json({
				error: "internal_error",
				error_description: "redirect policy not registered for provider",
			});
		}
		const redirect = policy.resolveCallbackRedirect({ redirectTo });
		if (!redirect.ok) {
			// A policy's refusal, in its words, held to RFC 6749's characters, and
			// a client error kept one (`refusalEnvelope`).
			return res.status(redirect.status).json(refusalEnvelope(redirect, log));
		}
		return res.redirect(redirect.value);
	};

	/**
	 * The callback leg, shared by the GET and POST routes; only the parameter
	 * source differs (query string for `"query"`, form body for
	 * `"form_post"`). One handler because it is the security boundary: two
	 * copies would be two places for the state check to drift.
	 */
	const runCallback = async (
		provider: FederationProvider,
		params: Readonly<Record<string, string>>,
		req: Request,
		res: Response,
	): Promise<unknown> => {
		// Per-handler logger child carrying the provider binding. After
		// `randomUUID()` produces `sid` below, we rebind to include `sid`
		// so subsequent calls do not need to repeat either field.
		let log = logger.child({ provider: provider.name });

		const responseMode = resolveFederationResponseMode(provider);

		// Where the ephemeral state lives: a `"query"` federation's in the
		// session (its callback is a same-site top-level GET carrying the
		// session cookie); a `"form_post"` federation's in a transaction record
		// addressed by its own cookie, because a cross-site POST does not carry
		// a `SameSite=Lax` session cookie. Without that cookie the callback is
		// refused before `state` is read, so a stolen `state` alone is worthless.
		let fed: FederationTransactionEnvelope | undefined;
		let transactions: FederationTransactionStore | undefined;
		let transactionId: string | undefined;

		/**
		 * Consume the transaction (cookie and record). Returns the store's error
		 * rather than throwing, so a refusal path can clean up best effort while
		 * irreversible work fails closed. A no-op for a `"query"` federation.
		 */
		const consumeTransaction = async (): Promise<unknown> => {
			if (!transactions || transactionId === undefined) return null;
			clearTransactionCookie(provider, res);
			const id = transactionId;
			transactionId = undefined;
			try {
				await transactions.delete(id);
				return null;
			} catch (err) {
				return err;
			}
		};

		/**
		 * Consume the transaction on a path that is refusing anyway: a failed
		 * delete is one `federation_cleanup_failed` warn, and the request's
		 * cookie session is dropped so express-session does not write to that
		 * store again.
		 */
		const discardTransaction = async (): Promise<void> => {
			const discardErr = await consumeTransaction();
			if (discardErr) {
				log.warn(
					{ store: "federation_transaction", step: "delete", err: loggableError(discardErr) },
					"federation_cleanup_failed",
				);
				abandonCookieSession(req);
			}
		};

		/**
		 * The cookie session's store (or a transaction in it) could not answer:
		 * log the outage first, then optionally discard the transaction (so a
		 * cleanup warn never precedes its cause), drop the cookie session, and
		 * answer `503`.
		 */
		const refuseCookieStoreOutage = async (
			store: "cookie_session" | "federation_transaction",
			step: FederationStoreStep,
			cause: unknown,
			{ discard = false }: { readonly discard?: boolean } = {},
		): Promise<unknown> => {
			logStoreUnavailable(log, "federation_callback_store_unavailable", store, step, cause);
			if (discard) await discardTransaction();
			abandonCookieSession(req);
			return res.status(503).json(SESSION_STORE_UNAVAILABLE);
		};

		if (responseMode === "form_post") {
			transactions = transactionStore(req);
			transactionId = readCookie(req, transactionCookieName);
			if (!transactions || transactionId === undefined || transactionId.length === 0) {
				// No transaction cookie, no transaction. This is the refusal an
				// attacker replaying a `state` from another browser meets.
				clearTransactionCookie(provider, res);
				return res.status(400).json({
					error: "invalid_session",
					error_description: "No active federation session for this provider",
				});
			}
			try {
				fed = (await transactions.get(transactionId)) ?? undefined;
			} catch (err) {
				return refuseCookieStoreOutage("federation_transaction", "get", err, { discard: true });
			}
		} else {
			fed = req.session.federation;
		}

		// Check the envelope is present and names this provider
		if (!fed || fed.name !== String(req.params.name)) {
			await discardTransaction();
			return res.status(400).json({
				error: "invalid_session",
				error_description: "No active federation session for this provider",
			});
		}

		// A refusal spends the transaction when the request made a claim about
		// it (presented a `state`, right or wrong: one guess is all there is),
		// and leaves it alone when it made none. The `form_post` transaction
		// cookie is `SameSite=None`, so it rides any cross-site request (an
		// `<img>` GET included); if a parameterless request spent it, a third
		// party could kill a victim's in-flight flow.
		//
		// A `query` federation's envelope lives in the session and is retired
		// only after `state` matches, so a wrong `state` leaves it in place: the
		// `SameSite=Lax` session cookie rides a top-level cross-site GET, so
		// retiring on a mismatch would hand any third party that same
		// availability attack. Unlimited guesses at a 128-bit CSPRNG `state` are
		// worth no more than one.
		if (typeof params.state !== "string" || params.state.length === 0) {
			return res.status(400).json({
				error: "invalid_request",
				error_description: "Missing state parameter",
			});
		}

		// CSRF state check — unchanged, and deliberately so: the transaction
		// cookie is an addition to this comparison, never a replacement for it.
		if (params.state !== fed.state) {
			await discardTransaction();
			return res.status(400).json({
				error: "invalid_state",
				error_description: "CSRF state mismatch",
			});
		}

		// Copy ephemeral state to locals, then retire it BEFORE any async work, so
		// a replay arriving after this callback finds nothing — including when
		// `exchangeCode` throws.
		const { codeVerifier, redirectTo, nonce } = fed;

		// Retirement is a read then a delete: the express-session Store API has
		// no atomic read-and-consume. A callback after an earlier one's delete
		// is refused (a replayed `code`/`state`, the back button, a retry), but
		// overlapping callbacks can both reach `exchangeCode`
		// (`Federation.transactionConcurrency.test.mts` pins this). The IdP
		// bounds that: an authorization code is single-use, and PKCE binds it to
		// the verifier in the record. A dedicated atomic store would need its
		// own component slot in every deployment, for a property the IdP already
		// provides. If the state cannot be retired at all, fail closed (503): a
		// forced delete failure plus a replay would otherwise face no reuse check.
		if (responseMode === "form_post") {
			const consumeErr = await consumeTransaction();
			if (consumeErr) {
				return refuseCookieStoreOutage("federation_transaction", "delete", consumeErr);
			}
		} else {
			delete req.session.federation;
			const reusePrevSaveErr = await new Promise<unknown>((resolve) => {
				req.session.save((err) => resolve(err ?? null));
			});
			if (reusePrevSaveErr) {
				return refuseCookieStoreOutage("cookie_session", "save", reusePrevSaveErr);
			}
		}

		// A missing or empty `code` is a 400, not an empty string sent to the IdP
		// (which would surface as a 502).
		const codeParam = params.code;
		if (typeof codeParam !== "string" || codeParam.length === 0) {
			return res.status(400).json({
				error: "invalid_request",
				error_description: "Missing authorization code",
			});
		}

		// Exchange the authorization code for a FederationProfile
		// providerCallbackUrls is the authoritative map; same entry verified above in the start handler.
		const callbackUrl = providerCallbackUrls.get(provider.name);
		if (!callbackUrl) {
			logMisconfigured(log, "no_callback_url");
			return res.status(500).json({
				error: "misconfiguration",
				error_description: sanitizeErrorText(
					`No callback URL registered for provider '${provider.name}'`,
				),
			});
		}

		// What the adapter sees of the callback, minus `code` (passed in its own
		// field) and `state` (already checked here): a generic bag carrying them
		// would be a second, unchecked place to read a credential from.
		const { code: _code, state: _state, ...adapterCallbackParams } = params;

		let profile: Awaited<ReturnType<FederationProvider["exchangeCode"]>>;
		try {
			profile = await provider.exchangeCode({
				code: codeParam,
				codeVerifier,
				redirectUri: callbackUrl,
				// The session-stored nonce, so OIDC adapters bind the id_token via
				// `expectedNonce`; OAuth-only adapters ignore it.
				nonce,
				// The remaining callback parameters, so an adapter can read identity
				// an IdP delivers beside the token response (Apple's first-login
				// `user` body — unsigned, so `mapClaims` and claim precedence decide
				// what it may affect) or RFC 9207's `iss`.
				callbackParams: adapterCallbackParams,
			});
		} catch (err) {
			// The upstream's verdict or outage, not this server's: a warn. The
			// error's cause chain can hold the refused token response, so only its
			// projection is logged.
			log.warn({ err: loggableError(err) }, "federation_callback_exchange_failed");
			return res.status(502).json({
				error: "exchange_failed",
				error_description: "Token exchange with upstream IdP failed",
			});
		}

		if (!profile.sub) {
			return res.status(400).json({
				error: "invalid_profile",
				error_description: "Federation profile is missing sub claim",
			});
		}

		const identityToken = `${provider.name}:${profile.sub}`;
		let user: Awaited<ReturnType<typeof userRepository.authenticateByToken>>;
		try {
			user = await userRepository.authenticateByToken(identityToken);
		} catch (err) {
			logStoreUnavailable(
				log,
				"federation_callback_store_unavailable",
				"user_repository",
				"authenticate_by_token",
				err,
			);
			return res.status(503).json(USER_DIRECTORY_UNAVAILABLE);
		}
		// An explicit link request completes or is refused here; it never falls
		// through to the login path below: a link is not a login.
		if (fed.link !== undefined) {
			return completeLink(
				provider,
				profile,
				identityToken,
				user,
				redirectTo,
				fed.link,
				req,
				res,
				log,
			);
		}

		if (!user) {
			return res.status(401).json({
				error: "unknown_user",
				error_description: "No local account linked to this federated identity",
			});
		}

		// Build claims. The local record is authoritative; the provider's mapped
		// claims may fill a promotable field it left absent, and are otherwise
		// recorded under `claims.federated[<provider>]` rather than merged into
		// the envelope this deployment authorizes on.
		const claims = mergeFederatedClaims({
			localClaims: extractUserClaims(user),
			providerName: provider.name,
			mappedClaims: supportsClaimMapping(provider) ? provider.mapClaims(profile) : undefined,
		});

		// `establishSession` writes the login's tail. This callback adds two
		// steps — the federation's index entry before the regeneration and the
		// upstream tokens after it, each undone in reverse when a later write
		// fails — and logs in this router's vocabulary. The index entry is not
		// atomic with the record: a failed `addFederation` rolls the record back
		// and the user logs in again (an atomic compound call would re-couple
		// the stores). Regeneration comes after the record and index exist and
		// before tokens or session fields are written.
		const accessToken = profile.accessToken;
		const attachTokens: ReadonlyArray<EstablishSessionStep<FederationStore, FederationStoreStep>> =
			accessToken
				? [
						{
							store: "federation_token",
							step: "attach",
							run: ({ sid }) => {
								// `profile.expiresAt` is `Date | null` (required on
								// FederationProfile). `null` propagates to the store and
								// signals "do not refresh; reuse" — the route layer never
								// invents a fallback expiry.
								const consented = consentedScope(profile.scope, provider.scope);
								return federationTokenStore.attach(sid, provider.name, {
									accessToken,
									refreshToken: profile.refreshToken,
									idToken: profile.idToken,
									expiresAt: profile.expiresAt,
									// As above: the consented scope, and the ceiling it sets.
									scope: consented,
									grantedScope: consented,
									// As above: recorded, not judged; the disclosing route decides.
									tokenType: recordedTokenType(profile.tokenType),
								});
							},
							undo: {
								step: "delete",
								run: ({ sid }) => federationTokenStore.delete(sid, provider.name),
							},
						},
					]
				: [];

		// The callback does not consult admission: an interruption here would
		// have to be a navigation carrying the upstream tokens. Core builds the
		// establishment without asking, from the federation's facts; `recorded`
		// is core's (`fed`, with a trusted IdP's `amr` beside it or an untrusted
		// one's kept apart), keyed by `fed.name`. No `redirectTo`: the callback
		// redirects by its policy below.
		const establishment = establishWithoutAsking({
			subject: user.id,
			user,
			claims,
			federation: fed.name,
			upstreamAmr: upstreamAmrOf(profile),
			trusted: trustsUpstreamAmr.get(fed.name) === true,
			authTime: new Date(),
			redirectTo: undefined,
			request: loginRequestFacts(req),
		});
		const established = await establishSession<FederationStore, FederationStoreStep>(
			establishment,
			{
				req,
				userSessionStore,
				...(subjectSessionIndex === undefined ? {} : { subjectSessionIndex }),
				sessionTtlMs,
				beforeRegenerate: [
					{
						store: "session_federation_index",
						step: "add",
						run: ({ sid, expiresAt }) =>
							sessionFederationIndex.addFederation(sid, provider.name, expiresAt),
						undo: {
							step: "remove_by_sid",
							run: ({ sid }) => sessionFederationIndex.removeBySid(sid),
						},
					},
				],
				afterRegenerate: attachTokens,
				reporter: ({ sid }) => {
					// Rebind: from this point onward, every log call carries
					// `provider` AND `sid` — the lines the tail emits, and this
					// callback's own after it.
					log = log.child({ sid });
					return {
						storeUnavailable: (store, step, cause) =>
							logStoreUnavailable(log, "federation_callback_store_unavailable", store, step, cause),
						cleanupFailed: (store, step, cause) => logCleanupFailed(log, store, step, cause),
						subjectIndexWriteFailed: (cause) =>
							log.error(
								{ err: loggableError(cause), sub: user.id },
								"subject_session_index_write_failed",
							),
					};
				},
			},
		);
		if (established.outcome === "unavailable") {
			return res.status(503).json(SESSION_STORE_UNAVAILABLE);
		}

		// Resolve the redirect URL via the federation's redirect policy.
		const callbackPolicy = federationRedirectPolicyResolver.get(provider.name);
		if (!callbackPolicy) {
			logMisconfigured(log, "no_redirect_policy");
			return res.status(500).json({
				error: "internal_error",
				error_description: "redirect policy not registered for provider",
			});
		}
		const redirectResult = callbackPolicy.resolveCallbackRedirect({ redirectTo });
		if (!redirectResult.ok) {
			return res.status(redirectResult.status).json(refusalEnvelope(redirectResult, log));
		}

		return res.redirect(redirectResult.value);
	};

	/**
	 * Bind {@link runCallback} to a parameter source, gated on the provider's
	 * response mode: each federation has exactly one callback method, and the
	 * other answers `405` rather than being parsed as a callback.
	 */
	const callbackHandler =
		(source: "query" | "body") =>
		async (req: Request, res: Response): Promise<unknown> => {
			const provider = federationProviders.get(String(req.params.name));
			if (!provider) {
				return res
					.status(404)
					.json(
						errorEnvelope(
							"not_found",
							`Federation provider not registered: ${String(req.params.name)}`,
						),
					);
			}

			const providerResponseMode = resolveFederationResponseMode(provider);

			if (source === "body" && providerResponseMode !== "form_post") {
				return res
					.status(405)
					.set("Allow", "GET")
					.json({
						error: "method_not_allowed",
						error_description: sanitizeErrorText(
							`Federation '${provider.name}' returns its authorization response in the query string; the POST callback is accepted only for a form_post federation`,
						),
					});
			}

			// A form_post IdP only POSTs here; a GET is a misconfiguration or a
			// probe carrying the victim's `SameSite=None` transaction cookie.
			// Refused before the cookie is read, so a third party's `<img>` never
			// reaches the transaction.
			if (source === "query" && providerResponseMode === "form_post") {
				return res
					.status(405)
					.set("Allow", "POST")
					.json({
						error: "method_not_allowed",
						error_description: sanitizeErrorText(
							`Federation '${provider.name}' returns its authorization response as a form post; the GET callback is accepted only for a query federation`,
						),
					});
			}

			return runCallback(
				provider,
				readCallbackParams(source === "body" ? req.body : req.query),
				req,
				res,
			);
		};

	router
		// This router's own paths, exactly: it is mounted at `/session`, a prefix
		// other modules mount routes under too, and a `.use` parser would read
		// their bodies as well.
		.all(
			["/oauth/federation/:name", "/oauth/federation/:name/callback"],
			express.json(),
			express.urlencoded({ extended: false }),
		)

		// ------------------------------------------------------------------
		// GET /oauth/federation/:name  — start the OAuth 2 redirect leg
		// ------------------------------------------------------------------
		.get("/oauth/federation/:name", async (req: Request, res: Response) => {
			const provider = federationProviders.get(String(req.params.name));
			if (!provider) {
				return res
					.status(404)
					.json(
						errorEnvelope(
							"not_found",
							`Federation provider not registered: ${String(req.params.name)}`,
						),
					);
			}

			const { redirect_to } = req.query;

			let redirectTo: string | undefined;
			if (redirect_to != null) {
				if (typeof redirect_to !== "string") {
					return res.status(400).json({
						error: "invalid_redirect",
						error_description: "redirect_to must be a string",
					});
				}
				const policy = federationRedirectPolicyResolver.get(provider.name);
				if (!policy) {
					// Pairing invariant fires at boot; this branch is defence-in-depth
					// against a hypothetical bug bypassing the invariant at runtime.
					logMisconfigured(logger, "no_redirect_policy", { provider: provider.name });
					return res.status(500).json({
						error: "internal_error",
						error_description: "redirect policy not registered for provider",
					});
				}
				const validation = policy.validateRedirect(redirect_to);
				if (!validation.ok) {
					return res
						.status(validation.status)
						.json(refusalEnvelope(validation, logger, { provider: provider.name }));
				}
				redirectTo = redirect_to;
			}

			// `link=1` asks to link this federation's identity to the signed-in
			// account. Explicit because a session cookie plus a stray identity is
			// the login-CSRF shape: signing in with another provider never links
			// by itself. Refused here, before any redirect, when it cannot succeed.
			const wantsLink = req.query.link === "1" || req.query.link === "true";
			let link: LinkIntent | undefined;
			if (wantsLink) {
				// A link changes an existing account, so the user must be the one
				// asking: a top-level cross-site navigation carries the SameSite=Lax
				// cookie, and a forced `?link=1` paired with a login CSRF at the IdP
				// would link the attacker's identity to the victim's account. The
				// evidence is the session CSRF policy's navigation rule
				// (`checkNavigationOrigin`). An ordinary login start is not held to
				// this: cross-domain RPs starting a login is normal.
				if (checkNavigationOrigin(req, linkTrustedOrigins).outcome !== "accepted") {
					logger.warn(
						{
							provider: provider.name,
							// The caller's header, sanitised and capped like every
							// caller-controlled string on a log line.
							secFetchSite: auditErrorText(req.get("sec-fetch-site") ?? ""),
						},
						"federation_link_start_rejected",
					);
					return res.status(403).json({
						error: "link_requires_trusted_origin",
						error_description:
							"Linking a federated identity must be started from this site or an origin on session.csrf.trustedOrigins",
					});
				}
				// A Store that cannot link is the composition's fault, not the
				// session's: said first, before the session is read — a static
				// fault answers the same whatever the session store is doing.
				if (typeof userRepository.linkFederatedIdentity !== "function") {
					return res.status(400).json({
						error: "link_unsupported",
						error_description: "The user repository does not support linking federated identities",
					});
				}
				// Admitted as `session.link`, graded `credential_change` (a linked
				// identity is a new way into the account), so a recent-authentication
				// rule is decided here, where a step-up has a page to return to.
				const claim = cookieClaim(req);
				const admission = await admitLink(
					claim,
					"session.link",
					logger.child({ provider: provider.name }),
				);
				if (admission.outcome === "unavailable") {
					return res.status(503).json(admissionUnavailable(admission.store));
				}
				if (admission.outcome === "step_up") {
					return res.status(403).json(stepUpRequired(admission));
				}
				if (
					admission.outcome !== "admitted" ||
					admission.session === null ||
					claim.sid === undefined
				) {
					return res.status(401).json({
						error: "login_required",
						error_description: "Linking a federated identity requires an authenticated session",
					});
				}
				// Recorded in the transaction, not inferred later: the cookie's `sid`
				// and the admitted subject. A form_post callback arrives without the
				// session cookie, and a browser that switched accounts must not link
				// to the new one.
				link = { sid: claim.sid, subject: admission.session.sub };
			}

			const responseMode = resolveFederationResponseMode(provider);

			// CSRF state, PKCE verifier and OIDC nonce. The nonce is generated for
			// every provider; OAuth-only adapters ignore it.
			const state = randomBytes(16).toString("base64url");
			const codeVerifier = generateCodeVerifier();
			const nonce = randomBytes(16).toString("base64url");

			// The authoritative callback URL map, from config. Read before any
			// state is persisted: a form_post start scopes its cookie to this path.
			const callbackUrl = providerCallbackUrls.get(provider.name);
			if (!callbackUrl) {
				logMisconfigured(logger, "no_callback_url", { provider: provider.name });
				return res.status(500).json({
					error: "misconfiguration",
					error_description: sanitizeErrorText(
						`No callback URL registered for provider '${provider.name}'`,
					),
				});
			}

			const envelope = {
				name: provider.name,
				state,
				codeVerifier,
				nonce,
				redirectTo,
				...(link === undefined ? {} : { link }),
			};

			// A form_post callback is a cross-site POST, which does not carry a
			// SameSite=Lax cookie, so its state travels as a transaction: an opaque
			// id in a short-lived, path-scoped SameSite=None cookie, with the
			// envelope in a store record. The application session cookie is never
			// touched here: this route is unauthenticated and reachable through any
			// third-party link, and express-session persists `req.session.cookie`.
			if (responseMode === "form_post") {
				const transactions = transactionStore(req);
				const cookiePath = transactionCookiePath(provider);
				if (!transactions || cookiePath === undefined) {
					// The composition's fault, not an outage: a form_post federation
					// whose request carries no express-session store, or whose
					// callback URL has no path to scope the cookie to, cannot check
					// state on the cross-site callback it would be sent.
					logMisconfigured(logger, transactions ? "no_callback_path" : "no_session_store", {
						provider: provider.name,
						callbackUrl,
					});
					return res.status(500).json({
						error: "misconfiguration",
						error_description: sanitizeErrorText(
							`Federation '${provider.name}' cannot start: no session store is mounted to hold its transaction`,
						),
					});
				}

				const transactionId = mintFederationTransactionId();
				// Persist the transaction BEFORE redirecting to the IdP, for the
				// same reason the query branch saves the session here: an async
				// store that loses the record before the user reaches the callback
				// breaks CSRF + PKCE + nonce binding, and failing closed on a store
				// outage is cheaper than a stranded callback.
				try {
					await transactions.set(transactionId, envelope, federationTransactionTtlMs);
				} catch (err) {
					logStoreUnavailable(
						logger,
						"federation_start_store_unavailable",
						"federation_transaction",
						"set",
						err,
						{ provider: provider.name },
					);
					abandonCookieSession(req);
					return res.status(503).json(SESSION_STORE_UNAVAILABLE);
				}

				res.cookie(transactionCookieName, transactionId, {
					...transactionCookieAttributes(cookiePath),
					// Expires with the record it addresses, so an abandoned flow
					// leaves neither behind.
					maxAge: federationTransactionTtlMs,
				});
			} else {
				// Persist ephemeral federation state in the session
				req.session.federation = envelope;

				// Persist the federation envelope BEFORE redirecting to the IdP. Without an explicit
				// save, async session stores (Redis, etc.) can lose the state/codeVerifier/nonce
				// before the user reaches the callback, breaking CSRF + PKCE + nonce binding —
				// fail-closed on store outages here is cheaper than a stranded callback.
				const startSaveErr = await new Promise<unknown>((resolve) => {
					req.session.save((err) => resolve(err ?? null));
				});
				if (startSaveErr) {
					logStoreUnavailable(
						logger,
						"federation_start_store_unavailable",
						"cookie_session",
						"save",
						startSaveErr,
						{ provider: provider.name },
					);
					abandonCookieSession(req);
					return res.status(503).json(SESSION_STORE_UNAVAILABLE);
				}
			}

			const authUrl = provider.buildAuthorizationUrl({
				redirectUri: callbackUrl,
				state,
				codeVerifier,
				nonce,
			});

			// The route, not the adapter, writes `response_mode`, keeping it paired
			// with the POST callback and the cookie decisions. Nothing is appended
			// for query mode, so that URL is exactly what the adapter returned.
			if (responseMode !== "query") {
				authUrl.searchParams.set("response_mode", responseMode);
			}

			return res.redirect(authUrl.toString());
		})

		// ------------------------------------------------------------------
		// GET  /oauth/federation/:name/callback  — query-mode callback
		// POST /oauth/federation/:name/callback  — form_post-mode callback
		//
		// Both are always mounted; `callbackHandler` refuses (405) the method a
		// federation's response mode does not use.
		// ------------------------------------------------------------------
		.get("/oauth/federation/:name/callback", callbackHandler("query"))
		.post("/oauth/federation/:name/callback", callbackHandler("body"));

	return router;
};
