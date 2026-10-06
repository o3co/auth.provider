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
 * The federation router: the start, `GET /oauth/federation/:name`, and the
 * callback, `GET` for a `query` federation and `POST` for `form_post`. It
 * builds the stages' context once and runs the callback's stages in order,
 * stopping at the first that answers. The login stays here: a session
 * established via `establishSession` from what `establishWithoutAsking`
 * builds. Core's guards pin that call and the `profile.amr` reads to this file.
 */

import {
	type AuditSink,
	admitSession,
	checkResolver,
	consoleLogger,
	establishWithoutAsking,
	type FederationProvider,
	type FederationSettings,
	type FederationTokenStore,
	type Logger,
	loggableError,
	readUserSnapshot,
	type SessionClaim,
	type SessionFederationIndex,
	type SessionLifecycle,
	type SessionLifecycleStore,
	type SessionRequirementResolver,
	type SubjectRevocation,
	type SubjectSessionIndex,
	supportsClaimMapping,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { SESSION_ADMISSION_ACTIONS, type SessionAdmissionAction } from "../admissionActions.mjs";
import { type EstablishSessionStep, establishSession } from "../establish-session.mjs";
import { mergeFederatedClaims } from "../federations/claim-precedence.mjs";
import { consentedScope } from "../federations/consented-scope.mjs";
import type { FederationRedirectPolicy } from "../federations/redirect-policy.mjs";
import {
	DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
	type LinkIntent,
} from "../federations/transaction.mjs";
import { SESSION_STORE_UNAVAILABLE } from "../internal/cookieSession.mjs";
import { extractUserClaims } from "../internal/extractUserClaims.mjs";
import { loginRequestFacts } from "../internal/loginRequest.mjs";
import { identifyFederatedUser } from "./FederationCallbackIdentity.mjs";
import { readCallbackParams, resolveCallbackProvider } from "./FederationCallbackRequest.mjs";
import { consumeCallbackState } from "./FederationCallbackState.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";
import { completeLink, recordedTokenType } from "./FederationLinkCallback.mjs";
import {
	type FederationStore,
	type FederationStoreStep,
	logCleanupFailed,
	logStoreUnavailable,
} from "./FederationLog.mjs";
import { redirectAfterCallback } from "./FederationRedirectAnswer.mjs";
import { createStartHandler } from "./FederationStart.mjs";
import { createTransactionCookie } from "./FederationTransactionCookie.mjs";

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
 * The upstream IdP's own `amr` (when the provider surfaces the id_token's as
 * a string array), else nothing. Whether it counts is the federation's
 * `trustUpstreamAmr`: core records it beside `fed` for a trusted federation
 * and apart from the session's `amr` otherwise.
 */
const upstreamAmrOf = (profile: Readonly<Record<string, unknown>>): readonly string[] =>
	Array.isArray(profile.amr) && profile.amr.every((v) => typeof v === "string")
		? (profile.amr as string[])
		: [];

export const createRouter = (
	express: {
		Router: () => Router;
		json: () => RequestHandler;
		urlencoded: (opts: { extended: boolean }) => RequestHandler;
	},
	{
		federationSettings,
		linkTrustedOrigins = [],
		federationProviders,
		federationRedirectPolicyResolver,
		providerCallbackUrls,
		userRepository,
		userSessionStore,
		subjectSessionIndex,
		subjectRevocation,
		sessionLifecycleStore,
		sessionLifecycle,
		sessionFederationIndex,
		federationTokenStore,
		sessionTtlMs = DEFAULT_SESSION_TTL_MS,
		federationTransactionTtlMs = DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
		federationTransactionCookieName,
		requirements,
		auditSink,
		logger = consoleLogger,
	}: {
		/**
		 * Core's view of `core.federations` (the `federationSettings` slot):
		 * whether each installed federation's upstream `amr` counts.
		 */
		federationSettings: FederationSettings;
		/**
		 * The origins other than this site's own an account-link start may be
		 * navigated from: `session.csrf.trustedOrigins`. None when absent, so
		 * only this site's own pages can start a link.
		 */
		linkTrustedOrigins?: readonly string[];
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
		/** The session lifecycle port the link routes' admission reads after a live record, when wired. */
		sessionLifecycleStore?: SessionLifecycleStore | undefined;
		/**
		 * Core's session lifecycle: a federated login opens the session's
		 * lifecycle record in it, and a federation joins a session through it.
		 * Required, as `userSessionStore` is: a router built without it is
		 * refused.
		 */
		sessionLifecycle?: SessionLifecycle | undefined;
		sessionFederationIndex: SessionFederationIndex;
		federationTokenStore: FederationTokenStore;
		sessionTtlMs?: number;
		/**
		 * How long a `form_post` federation's transaction may sit unconsumed;
		 * bounds the cookie's `Max-Age` and the record's expiry together.
		 */
		federationTransactionTtlMs?: number;
		/**
		 * Name of the `form_post` transaction cookie: the deployment's session
		 * cookie name run through `deriveFederationTransactionCookieName`,
		 * so it inherits the operator's naming without inheriting a `__Host-`
		 * prefix this path-scoped cookie could not satisfy.
		 */
		federationTransactionCookieName: string;
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
	if (!federationSettings) throw new Error("federation routes require federationSettings");
	if (!federationTransactionCookieName) {
		throw new Error("federation routes require federationTransactionCookieName");
	}
	if (!sessionLifecycle) {
		throw new Error(
			"federation routes: userSessionStore is wired, but sessionLifecycle is not. Where a user-session store is wired, core's session lifecycle is required: a login opens its session's record in it, and a federation joins a session through it. Install sessionLifecycleModule from @o3co/auth-provider-core beside the session stores.",
		);
	}

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
				sessionLifecycleStore,
				requirements,
				acrTable: NO_ACR_TABLE,
				logger: log,
				auditSink,
			},
			{ claim, action },
		);

	// Whether each installed federation's upstream `amr` counts, read once at
	// composition from core's reading of `trustUpstreamAmr` — the one the
	// `acr` table uses, so a session's record and `/authorize`'s advertisement
	// agree. Keyed by the installed name the callback resolves by; a name the
	// settings do not hold trusts nothing.
	const trustsUpstreamAmr = new Map<string, boolean>(
		[...federationProviders.keys()].map((name) => [
			name,
			Object.hasOwn(federationSettings, name) &&
				federationSettings[name]?.trustsUpstreamAmr === true,
		]),
	);

	// Whether each installed federation's callback alone meets a freshness ask,
	// read once at composition from core's reading of `callbackMeetsFreshness`,
	// as `trustsUpstreamAmr` is.
	const callbackMeetsFreshness = new Map<string, boolean>(
		[...federationProviders.keys()].map((name) => [
			name,
			Object.hasOwn(federationSettings, name) &&
				federationSettings[name]?.callbackMeetsFreshness === true,
		]),
	);

	const ctx: FederationRouterContext = {
		federationProviders,
		federationRedirectPolicyResolver,
		providerCallbackUrls,
		userRepository,
		sessionFederationIndex,
		federationTokenStore,
		sessionLifecycle,
		federationTransactionTtlMs,
		auditSink,
		logger,
		linkTrustedOrigins,
		admitLink,
		...createTransactionCookie(providerCallbackUrls, federationTransactionCookieName),
	};

	/**
	 * The callback leg, shared by the GET and POST routes; only the parameter
	 * source differs (query string for `"query"`, form body for
	 * `"form_post"`). One handler because it is the security boundary: two
	 * copies would be two places for the state check to drift. The state
	 * check, then the identity, then the link or the login; a stage that
	 * answers returns `null`, and the handler stops there.
	 */
	const runCallback = async (
		provider: FederationProvider,
		params: Readonly<Record<string, string>>,
		req: Request,
		res: Response,
	): Promise<unknown> => {
		// Bound to the provider; the login's reporter rebinds it with the `sid`
		// `establishSession` creates, so every later line carries both.
		let log = logger.child({ provider: provider.name });

		const fed = await consumeCallbackState(ctx, provider, params, req, res, log);
		if (fed === null) return;
		const { codeVerifier, redirectTo, nonce } = fed;

		const identity = await identifyFederatedUser(
			ctx,
			provider,
			params,
			codeVerifier,
			nonce,
			res,
			log,
		);
		if (identity === null) return;
		const { profile, identityToken, user, lifetime, upstreamAuthTime } = identity;

		// An explicit link request completes or is refused here; it never falls
		// through to the login path below: a link is not a login.
		if (fed.link !== undefined) {
			return completeLink(
				ctx,
				provider,
				profile,
				lifetime,
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

		// The login's one read of the user: everything after reads the
		// snapshot. A user core refuses is the route's error, a 500.
		const reading = readUserSnapshot(user);
		if (!reading.ok) {
			const field = reading.refused === "not_plain_data" ? ` (${reading.field})` : "";
			throw new RangeError(`federation callback: the user is refused: ${reading.refused}${field}`);
		}
		const { snapshot } = reading;

		// Build claims. The local record is authoritative; the provider's mapped
		// claims may fill a promotable field it left absent, and are otherwise
		// recorded under `claims.federated[<provider>]` rather than merged into
		// the envelope this deployment authorizes on.
		const claims = mergeFederatedClaims({
			localClaims: extractUserClaims(snapshot),
			providerName: provider.name,
			mappedClaims: supportsClaimMapping(provider) ? provider.mapClaims(profile) : undefined,
		});

		// `establishSession` writes the login's tail. This callback adds its
		// steps after the regeneration — the upstream tokens, then the
		// lifecycle's join — the tokens undone when a later write fails, and
		// logs in this router's vocabulary. A failed write rolls the session
		// back, its lifecycle record closed, and the user logs in again.
		// Regeneration comes after the record exists and before tokens or
		// session fields are written.
		const accessToken = profile.accessToken;
		const attachTokens: ReadonlyArray<EstablishSessionStep<FederationStore, FederationStoreStep>> =
			accessToken
				? [
						{
							store: "federation_token",
							step: "attach",
							run: ({ sid }) => {
								const consented = consentedScope(profile.scope, provider.scope);
								return federationTokenStore.attach(sid, provider.name, {
									accessToken,
									refreshToken: profile.refreshToken,
									idToken: profile.idToken,
									// The end as core's reading dates it, and when the token was
									// obtained if that end counts from this server's call. A
									// `null` end means "do not refresh; reuse": the route layer
									// never invents a fallback expiry.
									...lifetime,
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
		const establishment = establishWithoutAsking(
			{
				subject: snapshot.id,
				user: snapshot,
				claims,
				federation: fed.name,
				upstreamAmr: upstreamAmrOf(profile),
				trusted: trustsUpstreamAmr.get(fed.name) === true,
				// The upstream's authentication time (the verified id_token's
				// `auth_time`), and whether this federation's callback alone meets a
				// freshness ask when there is none; core records either as it reads them.
				...(upstreamAuthTime === undefined ? {} : { upstreamAuthTime }),
				callbackMeetsFreshness: callbackMeetsFreshness.get(fed.name) === true,
				authTime: new Date(),
				redirectTo: undefined,
				request: loginRequestFacts(req),
			},
			{ logger: log },
		);
		// The federation joins the session through core's session lifecycle
		// after its tokens are attached: a session closed before the join is
		// refused, and the lifecycle removes the tokens handed to it.
		let closed = false;
		const joined: EstablishSessionStep<FederationStore, FederationStoreStep> = {
			store: "session_lifecycle",
			step: "join",
			run: async ({ sid }) => {
				const answer = await sessionLifecycle.join(sid, { federation: provider.name });
				if (answer.outcome === "joined") return;
				closed = answer.outcome === "refused";
				throw new Error(`the session lifecycle answered ${answer.outcome} to the join`);
			},
		};
		const established = await establishSession<FederationStore, FederationStoreStep>(
			establishment,
			{
				req,
				userSessionStore,
				...(subjectSessionIndex === undefined ? {} : { subjectSessionIndex }),
				sessionLifecycle,
				sessionTtlMs,
				afterRegenerate: [...attachTokens, joined],
				reporter: ({ sid }) => {
					// Rebind: from this point onward, every log call carries
					// `provider` AND `sid` — the lines the tail emits, and this
					// callback's own after it.
					log = log.child({ sid });
					return {
						// A refused join is the session's close, not an outage.
						storeUnavailable: (store, step, cause) => {
							if (!closed) {
								logStoreUnavailable(
									log,
									"federation_callback_store_unavailable",
									store,
									step,
									cause,
								);
							}
						},
						cleanupFailed: (store, step, cause) => logCleanupFailed(log, store, step, cause),
						subjectIndexWriteFailed: (cause) =>
							log.error(
								{ err: loggableError(cause), sub: snapshot.id },
								"subject_session_index_write_failed",
							),
					};
				},
			},
		);
		if (established.outcome === "unavailable") {
			if (closed) {
				return res.status(401).json({
					error: "login_required",
					error_description: "The session ended before the sign-in completed",
				});
			}
			return res.status(503).json(SESSION_STORE_UNAVAILABLE);
		}

		return redirectAfterCallback(ctx, provider, redirectTo, res, log);
	};

	/**
	 * Bind {@link runCallback} to a parameter source, gated on the provider's
	 * response mode: each federation has exactly one callback method, and the
	 * other answers `405` rather than being parsed as a callback.
	 */
	const callbackHandler =
		(source: "query" | "body") =>
		async (req: Request, res: Response): Promise<unknown> => {
			const provider = resolveCallbackProvider(ctx, source, req, res);
			if (provider === null) return;

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
		.get("/oauth/federation/:name", createStartHandler(ctx))

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
