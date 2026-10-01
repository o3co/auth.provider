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
	errorEnvelope,
	establishWithoutAsking,
	type FederationProvider,
	type FederationTokenStore,
	federationTrustsUpstreamAmr,
	type Logger,
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
	DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
	deriveFederationTransactionCookieName,
	type LinkIntent,
	mintFederationTransactionId,
} from "../federations/transaction.mjs";
import {
	abandonCookieSession,
	admissionUnavailable,
	SESSION_STORE_UNAVAILABLE,
} from "../internal/cookieSession.mjs";
import { extractUserClaims } from "../internal/extractUserClaims.mjs";
import { loginRequestFacts } from "../internal/loginRequest.mjs";
import { refusalEnvelope } from "../internal/refusalEnvelope.mjs";
import { identifyFederatedUser } from "./FederationCallbackIdentity.mjs";
import { readCallbackParams, resolveCallbackProvider } from "./FederationCallbackRequest.mjs";
import { consumeCallbackState } from "./FederationCallbackState.mjs";
import { type FederationRouterContext, recordedTokenType } from "./FederationContext.mjs";
import { completeLink } from "./FederationLinkCallback.mjs";
import {
	type FederationStore,
	type FederationStoreStep,
	logCleanupFailed,
	logMisconfigured,
	logStoreUnavailable,
} from "./FederationLog.mjs";
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

/** Read `config.session.csrf.trustedOrigins` without assuming a full AppConfig. */
const readCsrfTrustedOrigins = (config: unknown): readonly string[] => {
	const csrf = (config as { session?: { csrf?: { trustedOrigins?: unknown } } } | null | undefined)
		?.session?.csrf;
	const list = csrf?.trustedOrigins;
	return Array.isArray(list) ? list.filter((o): o is string => typeof o === "string") : [];
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

	const {
		transactionStore,
		transactionCookiePath,
		transactionCookieAttributes,
		clearTransactionCookie,
	} = createTransactionCookie(providerCallbackUrls, transactionCookieName);

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
		transactionCookieName,
		transactionStore,
		transactionCookiePath,
		transactionCookieAttributes,
		clearTransactionCookie,
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
