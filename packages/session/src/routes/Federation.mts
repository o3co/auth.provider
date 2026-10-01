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
	type AppConfig,
	type AuditSink,
	admitSession,
	checkResolver,
	consoleLogger,
	establishWithoutAsking,
	type FederationProvider,
	type FederationTokenStore,
	federationTrustsUpstreamAmr,
	type Logger,
	loggableError,
	type SessionClaim,
	type SessionFederationIndex,
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
	deriveFederationTransactionCookieName,
	type LinkIntent,
} from "../federations/transaction.mjs";
import { SESSION_STORE_UNAVAILABLE } from "../internal/cookieSession.mjs";
import { extractUserClaims } from "../internal/extractUserClaims.mjs";
import { loginRequestFacts } from "../internal/loginRequest.mjs";
import { identifyFederatedUser } from "./FederationCallbackIdentity.mjs";
import { redirectAfterCallback } from "./FederationCallbackRedirect.mjs";
import { readCallbackParams, resolveCallbackProvider } from "./FederationCallbackRequest.mjs";
import { consumeCallbackState } from "./FederationCallbackState.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";
import { completeLink, recordedTokenType } from "./FederationLinkCallback.mjs";
import { readCsrfTrustedOrigins } from "./FederationLinkStart.mjs";
import {
	type FederationStore,
	type FederationStoreStep,
	logCleanupFailed,
	logStoreUnavailable,
} from "./FederationLog.mjs";
import { createStartHandler } from "./FederationStart.mjs";
import { createTransactionCookie, readSessionCookieName } from "./FederationTransactionCookie.mjs";

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

	const ctx: FederationRouterContext = {
		federationProviders,
		federationRedirectPolicyResolver,
		providerCallbackUrls,
		userRepository,
		sessionFederationIndex,
		federationTokenStore,
		federationTransactionTtlMs,
		auditSink,
		logger,
		linkTrustedOrigins,
		admitLink,
		...createTransactionCookie(providerCallbackUrls, transactionCookieName),
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
		const { profile, identityToken, user } = identity;

		// An explicit link request completes or is refused here; it never falls
		// through to the login path below: a link is not a login.
		if (fed.link !== undefined) {
			return completeLink(
				ctx,
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
