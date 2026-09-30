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
 * The browser half of federation-grant acquisition, mounted at
 * `/session/federation-grants`: the connect start a client sends the user to,
 * the consent the deployment's page reads and answers, and the upstream callback.
 *
 * Connect and the callback are navigations: redirects and plain text, never a
 * JSON body. `GET`/`POST /consent` mirror `/oauth/consent` for the page that
 * already implements it: JSON data and errors, `401 login_required`, one
 * indistinguishable answer for any challenge with nothing behind it, and `303`
 * for both `POST` outcomes. None inherits the JSON router's client
 * authentication, 404 or throttle body.
 *
 * Connect is cross-site by construction, so it is not held to the navigation
 * rule the account-link start is (the `csrfGuard`'s `checkNavigation`), and
 * `session.csrf.trustedOrigins` is not widened to client origins; consent is
 * its CSRF defence. The answer is held to the deployment's `csrfGuard`
 * (`check`: this origin, as core's `CsrfGuard` defines it, or a trusted one,
 * or, naming no origin, the guard's double-submit token) and needs the
 * challenge AND the exact session binding. That holds only while connect never approves
 * or creates an upstream transaction, every grant and renewal (first-party
 * clients too) goes through consent, the consent data is never readable
 * cross-origin with credentials, the challenge never reaches another origin
 * via a referrer (`Referrer-Policy: no-referrer` on every response here; the
 * deployment's page keeps its own URL on its origin), and the answer
 * re-admits the session. Making consent skippable is a redesign of this
 * exemption.
 *
 * Whether the session may go on is core's `admitSession` on the cookie's claim,
 * as `federation_grants.connect`, `.consent` and `.callback` (the callback asks
 * twice: before the exchange and before activation). This file checks the
 * flow's own conditions: the intent's subject, the browser binding (express
 * session id and durable `sid`), the grant's current intent, the client's
 * permission, the connection's pins and the grants boundary. Anything admission
 * refuses, `step_up` included, gets the dead-session answer (connect: plain
 * `403`; consent: `403 reauthentication_required`; callback:
 * `error=reauthentication_required`); an unauthenticated cookie at connect is
 * sent to login instead.
 *
 * Every `503` and every callback `temporarily_unavailable` redirect writes one
 * error line, `federation_grant_{connect,consent,callback}_unavailable`, with
 * `store` and `step` (or `reason`). Admission, the client registry and the
 * throttle log their own outages through core; a failure that changed no answer
 * is one warn.
 */

import {
	type ClientRepository,
	type CsrfVerdict,
	checkCanonicalIssuer,
	checkResolver,
	checkWithFailMode,
	coveredByRevocationBoundary,
	createRateLimitPolicy,
	describeAdmissionOutage,
	describeIssuerRejection,
	type FederatedIdentityLookupResult,
	type FederationGrantAcquisitionConnection,
	type FederationGrantConnectTransaction,
	type FederationGrantIntent,
	type FederationGrantIntentStore,
	type FederationGrantStore,
	federationGrantAuditMetadata,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
	isFederationUpstreamOutage,
	judgeUpstreamAccessToken,
	parseScopeTokens,
} from "@o3co/auth-provider-core";
import express, { type Request, type RequestHandler, type Response, type Router } from "express";
import { federationGrantIdentityRegistration } from "./acquisitionSettings.mjs";
import {
	type CallbackError,
	clientReturn,
	jsonError,
	NO_PENDING,
	noStoreNoReferrer,
	plain,
} from "./browserAnswers.mjs";
import { createConnectHandler } from "./browserConnect.mjs";
import {
	createBrowserFlow,
	type FederationGrantBrowserRouterOptions,
	type FederationGrantDelegatedAuthorizer,
	type Unanswered,
} from "./browserFlow.mjs";
import {
	CALLBACK,
	CONNECT,
	CONSENT,
	judge,
	judgementUnavailable,
	sessionHolds,
} from "./browserJudgement.mjs";
import { callbackParamsOf, claimOf, sessionIdOf, single } from "./browserRequest.mjs";
import { createRequestIdMiddleware, requestIdOf } from "./requestId.mjs";
import { parserRefusals, unexpectedErrors } from "./routes.mjs";

export type {
	FederationGrantBrowserRouterOptions,
	FederationGrantDelegatedAuthorizer,
} from "./browserFlow.mjs";

/** Where this router is mounted. */
export const FEDERATION_GRANTS_BROWSER_MOUNT_PATH = "/session/federation-grants";

/** The limiter tag; a budget of its own, apart from the JSON routes'. */
export const FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX = "federation_grants_browser";

const BODY_LIMIT = "8kb";

/**
 * Why the consent answer was refused: the `csrfGuard`'s reason, or
 * `unrecognized` for a verdict outside its contract.
 */
type CsrfRefusalReason = Extract<CsrfVerdict, { outcome: "refused" }>["reason"] | "unrecognized";

/** The consent answer's `error_description` for each {@link CsrfRefusalReason}. */
const CSRF_REFUSAL: Readonly<Record<CsrfRefusalReason, string>> = Object.freeze({
	foreign_origin: "cross-site answer refused",
	token_absent: "no origin and no valid csrf token",
	token_invalid: "no origin and no valid csrf token",
	unrecognized: "cross-site answer refused",
});

/**
 * The guard's verdict read fail-closed: `null` for an acceptance, otherwise
 * why not. Only `{ outcome: "accepted" }` accepts; a promise, another outcome
 * or an unknown reason refuses, and a promise's rejection is handled here.
 */
function csrfRefusal(verdict: unknown): CsrfRefusalReason | null {
	const read = verdict as { readonly outcome?: unknown; readonly reason?: unknown } | null;
	if (typeof (verdict as { then?: unknown } | null)?.then === "function") {
		(verdict as PromiseLike<unknown>).then(undefined, () => undefined);
		return "unrecognized";
	}
	if (read?.outcome === "accepted") return null;
	const reason = read?.outcome === "refused" ? read.reason : undefined;
	return typeof reason === "string" && Object.hasOwn(CSRF_REFUSAL, reason)
		? (reason as CsrfRefusalReason)
		: "unrecognized";
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

export function createFederationGrantBrowserRouter(
	options: FederationGrantBrowserRouterOptions,
): Router {
	// Refused where the composition is assembled, not answered 500 on every
	// request: a missing resolver, or one the planner did not build.
	const requirements = checkResolver(options.requirements, "createFederationGrantBrowserRouter", [
		CONNECT,
		CONSENT,
		CALLBACK,
	]);
	// Admission reads the sessions boundary only when handed one; without it a
	// session the boundary has ended would be admitted, so a hand-built router
	// without it is refused.
	const subjectRevocation = options.subjectRevocation;
	if (typeof subjectRevocation !== "object" || subjectRevocation === null) {
		throw new TypeError(
			"createFederationGrantBrowserRouter: subjectRevocation is required — the sessions " +
				"boundary a session must have authenticated after (D13) is read through it",
		);
	}
	// Likewise the issuer every URL here is built on: one that is not an absolute
	// http(s) URL would make every request a 500.
	const issuerRejection = checkCanonicalIssuer(options.issuer);
	if (issuerRejection !== null) {
		throw new TypeError(
			`createFederationGrantBrowserRouter: issuer ${describeIssuerRejection(issuerRejection)} — it is oauth.jwt.issuer`,
		);
	}
	const flow = createBrowserFlow(options, requirements, subjectRevocation);
	const { now, randomId, log, admissionFor, auditFor, failed } = flow;
	const router = express.Router();

	// The deployment's own logger and audit sink: a limiter outage here is
	// logged and audited as on every other throttled route.
	const throttlePolicy = createRateLimitPolicy(
		{
			limiter: options.rateLimiter,
			tag: FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX,
			...(options.logger === undefined ? {} : { logger: options.logger }),
			...(options.auditSink === undefined ? {} : { auditSink: options.auditSink }),
		},
		"createFederationGrantBrowserRouter",
	);
	/** The browser budget: the outage policy is core's, the rendering is the transport's. */
	const throttle =
		(render: (res: Response, status: number) => void): RequestHandler =>
		async (req, res, next) => {
			const ip = req.ip ?? "unknown";
			const outcome = await checkWithFailMode(
				throttlePolicy,
				`${FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX}:ip:${ip}`,
				{
					ip,
					...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
				},
			);
			if (outcome.status === "unavailable") {
				if (outcome.failMode === "open") return next();
				return render(res, 503);
			}
			if (!outcome.decision.allowed) return render(res, 429);
			next();
		};

	/**
	 * Admits a handler into the shutdown drain, as the JSON routes are: an unadmitted
	 * callback could consume its transaction and then have the grant store closed
	 * under it before the credential is written. Once the drain has begun, new work
	 * is refused before it touches anything.
	 */
	const admitted =
		(render: (res: Response) => void, handler: RequestHandler): RequestHandler =>
		async (req, res, next) => {
			const release = options.background.admit();
			if (release === undefined) {
				render(res);
				return;
			}
			try {
				await handler(req, res, next);
			} finally {
				release();
			}
		};
	const shuttingDownPlain = (res: Response) => plain(res, 503, "Temporarily unavailable.");
	const shuttingDownJson = (res: Response) =>
		jsonError(res, 503, "service_unavailable", "shutting_down");

	router.use(noStoreNoReferrer);
	router.use(createRequestIdMiddleware());

	// --- GET /connect ---------------------------------------------------------
	router.get(
		"/connect",
		throttle((res, status) =>
			plain(res, status, status === 429 ? "Too many requests." : "Temporarily unavailable."),
		),
		admitted(shuttingDownPlain, createConnectHandler(flow)),
	);

	// --- GET / POST /consent -------------------------------------------------
	const consentThrottle = throttle((res, status) =>
		status === 429
			? jsonError(res, 429, "rate_limited", "provider")
			: jsonError(res, 503, "temporarily_unavailable", "rate_limiter"),
	);

	/**
	 * The parked question, if this browser may see it — or `null` after an
	 * answer has been sent. One reader for both methods, so that the page can
	 * learn nothing on GET that the POST would then refuse.
	 */
	const pendingFor = async (req: Request, res: Response, challenge: unknown) => {
		const claim = claimOf(req);
		if (!claim.authenticated) {
			jsonError(res, 401, "login_required", "no authenticated session");
			return null;
		}
		const presented = single(challenge);
		if (presented === undefined) {
			jsonError(res, 400, "invalid_request", "challenge is required");
			return null;
		}
		let consent: Awaited<ReturnType<FederationGrantIntentStore["getConsent"]>>;
		let intent: FederationGrantIntent | null = null;
		let step = "get_consent";
		try {
			consent = await options.intentStore.getConsent(presented, now());
			step = "get_intent";
			if (consent !== null)
				intent = await options.intentStore.getIntent(consent.intentHandle, now());
		} catch (error) {
			log.outage(
				"federation_grant_consent_unavailable",
				{
					method: req.method,
					correlationId: requestIdOf(res),
					reason: "storage",
					store: "federation_grant_intent",
					step,
				},
				error,
			);
			jsonError(res, 503, "temporarily_unavailable", "storage");
			return null;
		}
		const binding = consent?.binding;
		// Another browser's challenge reads exactly as no challenge at all.
		if (
			consent === null ||
			intent === null ||
			binding === undefined ||
			binding.sessionId !== sessionIdOf(req) ||
			binding.sid !== claim.sid ||
			binding.subject !== claim.subject
		) {
			jsonError(res, 400, "invalid_request", NO_PENDING);
			return null;
		}
		const judged = await judge(
			options,
			admissionFor({
				method: req.method,
				grantId: intent.grantId,
				correlationId: requestIdOf(res),
			}),
			req,
			claim,
			CONSENT,
			intent,
			now,
		);
		if (!judged.ok) {
			if (judged.reason === "unavailable" && judged.unanswered !== undefined) {
				judgementUnavailable(
					log,
					"consent",
					{ method: req.method, grantId: intent.grantId, correlationId: requestIdOf(res) },
					intent,
					judged.unanswered,
				);
			}
			failed(req, res, judged.reason, intent);
			if (judged.reason === "reauthentication_required") {
				jsonError(res, 403, "reauthentication_required", "sign in again to continue");
			} else if (judged.reason === "unavailable") {
				// The description names what failed: the client registry as the GET's own lookup
				// does, the session's part by core's `describeAdmissionOutage`, the route's own
				// stores as `storage`.
				jsonError(
					res,
					503,
					"temporarily_unavailable",
					judged.admissionStore !== undefined
						? describeAdmissionOutage(judged.admissionStore)
						: judged.unanswered?.store === "client"
							? "client registry unavailable"
							: "storage",
				);
			} else if (judged.reason === "connection_not_permitted") {
				jsonError(res, 403, "access_denied", "connection_not_permitted");
			} else {
				// Stale, changed, or another subject's: nothing here to answer.
				jsonError(res, 400, "invalid_request", NO_PENDING);
			}
			return null;
		}
		return { consent, intent, binding: judged.binding, challenge: presented };
	};

	// Admitted like the POST: the read touches the durable session, the intent store
	// and the client registry, which a drain must not close under it.
	router.get(
		"/consent",
		consentThrottle,
		admitted(shuttingDownJson, async (req, res) => {
			try {
				const found = await pendingFor(req, res, req.query.challenge);
				if (found === null) return;
				const { consent, intent } = found;
				let client: Awaited<ReturnType<ClientRepository["findById"]>>;
				try {
					client = await options.clientRepository.findById(intent.clientId);
				} catch (error) {
					log.clientRepositoryUnavailable("federation_grant_consent", intent.clientId, error);
					jsonError(res, 503, "temporarily_unavailable", "client registry unavailable");
					return;
				}
				const described = client as { clientName?: string; clientUri?: string } | null;
				res.status(200).json({
					challenge: consent.challenge,
					client_id: intent.clientId,
					...(described?.clientName === undefined ? {} : { client_name: described.clientName }),
					...(described?.clientUri === undefined ? {} : { client_uri: described.clientUri }),
					connection: intent.connection,
					scopes: [...consent.scopes],
					...(intent.resource === undefined ? {} : { resource: intent.resource }),
					// The grant's duration, counted from the answer; an absolute date computed now
					// would be an estimate the grant does not keep.
					grant_expires_in: Math.floor(consent.lifetimeMs / 1000),
					// What the page must tell the user, as data.
					continues_after_logout: true,
					expires_in: Math.max(
						0,
						Math.floor((consent.expiresAt.getTime() - now().getTime()) / 1000),
					),
				});
			} catch (error) {
				log.unexpected("consent", { method: req.method, correlationId: requestIdOf(res) }, error);
				jsonError(res, 500, "server_error", "unexpected_error");
			}
		}),
	);

	router.post(
		"/consent",
		consentThrottle,
		express.json({ limit: BODY_LIMIT }),
		express.urlencoded({ extended: false, limit: BODY_LIMIT }),
		parserRefusals,
		admitted(shuttingDownJson, async (req, res) => {
			try {
				// Asked before the route reads the session binding, the challenge or
				// the intent store, so a refused answer spends no consent.
				const refusal = csrfRefusal(options.csrfGuard.check(req));
				if (refusal !== null) {
					log.refused("federation_grant_consent_csrf_refused", {
						reason: refusal,
						correlationId: requestIdOf(res),
						origin: req.get("origin"),
					});
					jsonError(res, 403, "invalid_request", CSRF_REFUSAL[refusal]);
					return;
				}
				const body = (req.body ?? {}) as Record<string, unknown>;
				const found = await pendingFor(req, res, body.challenge);
				if (found === null) return;
				const { intent, binding, challenge } = found;
				/** What every line of this answer carries. */
				const context = {
					method: req.method,
					grantId: intent.grantId,
					correlationId: requestIdOf(res),
				};
				/** A `503` this answer gives: one line at error. */
				const consentUnavailable = (
					description: "storage" | "upstream_unavailable",
					at: { readonly store?: string; readonly step: string; readonly refusal?: string },
					...cause: [] | [unknown]
				): void => {
					log.outage(
						"federation_grant_consent_unavailable",
						{ ...context, reason: description, ...at },
						...cause,
					);
					jsonError(res, 503, "temporarily_unavailable", description);
				};
				/**
				 * The answer recorded, or `null` after a `503`: an intent store that
				 * cannot record it is its outage, not an unexpected error.
				 */
				const record = async (
					answer: Parameters<FederationGrantIntentStore["answerConsent"]>[0]["answer"],
				) => {
					try {
						return await options.intentStore.answerConsent({
							challenge,
							binding,
							answer,
							now: now(),
						});
					} catch (error) {
						consentUnavailable(
							"storage",
							{ store: "federation_grant_intent", step: "answer_consent" },
							error,
						);
						return null;
					}
				};
				const decision = body.decision;
				if (decision !== "accept" && decision !== "deny") {
					// Refused with the question still parked: nothing was answered.
					jsonError(res, 400, "invalid_request", "decision must be 'accept' or 'deny'");
					return;
				}

				if (decision === "deny") {
					const answered = await record({ decision: "deny" });
					if (answered === null) return;
					if (answered.outcome !== "denied") {
						jsonError(res, 400, "invalid_request", NO_PENDING);
						return;
					}
					if (intent.kind === "reauthorization") {
						// Only this renewal's pointer, never a newer one: a refusal for
						// a superseded intent must not end the intent that replaced it.
						try {
							await options.grantStore.retireIntent({
								grantId: intent.grantId,
								handle: intent.handle,
								now: now(),
							});
						} catch (error) {
							// The consent is already spent, so nothing can activate
							// through this pointer; it lapses with the flow budget.
							log.degraded(
								"federation_grant_consent_step_failed",
								{ ...context, store: "federation_grant", step: "retire_intent" },
								error,
							);
						}
					}
					failed(req, res, "access_denied", intent);
					res.redirect(303, clientReturn(intent, "access_denied"));
					return;
				}

				const authorizer = options.authorizerFor(intent.federation);
				if (authorizer === undefined) {
					// Boot refuses a connection whose federation lacks the
					// capability; reaching here is a composition fault, and nothing
					// has been spent.
					consentUnavailable("upstream_unavailable", { step: "authorizer" });
					return;
				}
				const state = randomId();
				const nonce = randomId();
				const codeVerifier = randomId();
				let upstream: URL;
				try {
					// Built BEFORE the answer is spent: a configuration fault in the
					// URL must not consume the user's consent.
					upstream = authorizer.buildDelegatedAuthorizationUrl({
						redirectUri: intent.callbackUri,
						state,
						codeVerifier,
						nonce,
						scopes: intent.scopes,
						...(intent.resource === undefined ? {} : { resource: intent.resource }),
						authorizationParams: intent.authorizationParams,
					});
				} catch (error) {
					consentUnavailable("upstream_unavailable", { step: "authorization_url" }, error);
					return;
				}
				const answered = await record({ decision: "accept", state, codeVerifier, nonce });
				if (answered === null) return;
				if (answered.outcome === "refused") {
					// A fault on this side, and nothing was thrown: the store names it.
					consentUnavailable("storage", {
						store: "federation_grant_intent",
						step: "answer_consent",
						refusal: answered.reason,
					});
					return;
				}
				if (answered.outcome !== "accepted") {
					jsonError(res, 400, "invalid_request", NO_PENDING);
					return;
				}
				// No transaction-store outage can reach this line: the redirect
				// upstream happens only once the transaction exists.
				res.redirect(303, upstream.href);
			} catch (error) {
				log.unexpected("consent", { method: req.method, correlationId: requestIdOf(res) }, error);
				jsonError(res, 500, "server_error", "unexpected_error");
			}
		}),
	);

	// --- GET /callback/:connection -----------------------------------------
	/**
	 * Where the upstream returns the browser. Query mode only: a `form_post` callback
	 * arrives without the session cookie, so check 3 could not run; boot refuses
	 * such a federation.
	 *
	 * Check 1's failures are a plain 400: there is nowhere trustworthy to send the
	 * browser. Every later failure redirects to the intent's `redirect_uri` with the
	 * client's `state`, the `grant_id` and one `CallbackError` code, never an
	 * upstream's description, a thrown message or anything the callback carried.
	 */
	router.get(
		"/callback/:connection",
		throttle((res, status) =>
			plain(res, status, status === 429 ? "Too many requests." : "Temporarily unavailable."),
		),
		admitted(shuttingDownPlain, async (req, res) => {
			const correlationId = requestIdOf(res);
			const audit = auditFor(req);
			let transaction: FederationGrantConnectTransaction | null;
			try {
				const state = single(req.query.state);
				const connectionName = single(req.params.connection);
				if (state === undefined || connectionName === undefined) {
					plain(res, 400, "This request is not valid.");
					return;
				}
				// 1. The transaction: exists, names this connection, and is spent
				// HERE, before any code is exchanged — two callbacks cannot both
				// get as far as the upstream.
				try {
					transaction = await options.intentStore.consumeTransaction({
						state,
						connection: connectionName,
						now: now(),
					});
				} catch (error) {
					log.outage(
						"federation_grant_callback_unavailable",
						{
							correlationId,
							reason: "storage",
							store: "federation_grant_intent",
							step: "consume_transaction",
						},
						error,
					);
					plain(res, 503, "Temporarily unavailable.");
					return;
				}
				if (transaction === null) {
					failed(req, res, "unknown_transaction");
					plain(res, 400, "This request has expired or has already been used. Start again.");
					return;
				}
			} catch (error) {
				log.unexpected("callback", { correlationId }, error);
				plain(res, 500, "Something went wrong.");
				return;
			}

			const { intent } = transaction;
			/** What this flow's events correlate by: the id its lodging carried. */
			const flowId = intent.correlationId;
			/** What every line of this callback carries: its grant, and THIS request's id. */
			const context = { grantId: intent.grantId, correlationId };
			/**
			 * What could not answer, behind the `temporarily_unavailable` redirect
			 * about to be sent: one line, at error.
			 */
			const outage = (unanswered: Unanswered): void =>
				log.outage(
					"federation_grant_callback_unavailable",
					{ ...context, reason: "storage", store: unanswered.store, step: unanswered.step },
					unanswered.error,
				);
			/** Every terminal outcome after check 1 ends here: the flow is over either way. */
			const finish = async (): Promise<void> => {
				try {
					await options.intentStore.finishIntent(intent.handle, now());
				} catch (error) {
					// Cannot undo anything, and the flow budget ends it regardless.
					log.degraded(
						"federation_grant_callback_step_failed",
						{ ...context, store: "federation_grant_intent", step: "finish_intent" },
						error,
					);
				}
			};
			/** `reason` is the audit's alone (`code/reason`); the client hears the code. */
			const fail = async (code: CallbackError, reason?: string): Promise<void> => {
				failed(req, res, reason === undefined ? code : `${code}/${reason}`, intent);
				await finish();
				res.redirect(303, clientReturn(intent, code));
			};

			try {
				const connection = options.connections.get(intent.connection);
				const at = now();

				// 2. Still the grant's current intent, within the flow's one deadline;
				// the configuration it was lodged against; and, for a renewal, the
				// grant it would renew still standing under the subject's boundary.
				let grantsBoundary: Date | null;
				let asking: Omit<Unanswered, "error"> = { store: "revocation_boundary", step: "read" };
				try {
					grantsBoundary = await readBoundary(options.grantsBoundary, intent.subject);
					asking = { store: "federation_grant", step: "is_current_intent" };
					if (!(await options.grantStore.isCurrentIntent(intent.grantId, intent.handle, at))) {
						await fail("grant_not_authorizable");
						return;
					}
				} catch (error) {
					outage({ ...asking, error });
					await fail("temporarily_unavailable");
					return;
				}
				if (!pinned(connection, intent)) {
					await fail("grant_not_authorizable");
					return;
				}
				if (intent.kind === "reauthorization") {
					const backstopped = await backstop(intent, grantsBoundary, audit, flowId);
					if (backstopped !== "clear") {
						if (backstopped !== "revoked") outage(backstopped.unanswered);
						await fail(
							backstopped === "revoked" ? "grant_not_authorizable" : "temporarily_unavailable",
						);
						return;
					}
				}

				// 3. The browser the flow started in, still live, the intent's
				// subject's, and signed in after the subject's sessions boundary.
				// One claim for both reads: the re-read below admits the same one.
				const claim = claimOf(req);
				const admission = admissionFor(context);
				const session = await sessionHolds(admission, req, claim, transaction);
				if (session !== "ok") {
					await fail(session === "unavailable" ? "temporarily_unavailable" : session);
					return;
				}

				// 4. The upstream's own answer, validated by the adapter. A repeated parameter is
				// a malformed response (RFC 6749 §3.1): dropping copies could hand the adapter a
				// response without the `iss` it sent, so RFC 9207's check would hinge on metadata.
				if (Object.values(req.query).some((value) => typeof value !== "string")) {
					await fail("upstream_error");
					return;
				}
				const upstreamError = single(req.query.error);
				if (upstreamError !== undefined) {
					await fail(upstreamError === "access_denied" ? "access_denied" : "upstream_error");
					return;
				}
				const code = single(req.query.code);
				const authorizer = options.authorizerFor(intent.federation);
				if (code === undefined || authorizer === undefined || connection === undefined) {
					await fail("upstream_error");
					return;
				}
				const calledAt = now().getTime();
				let exchanged: Awaited<
					ReturnType<FederationGrantDelegatedAuthorizer["exchangeDelegatedCode"]>
				>;
				try {
					exchanged = await authorizer.exchangeDelegatedCode({
						code,
						codeVerifier: transaction.codeVerifier,
						redirectUri: intent.callbackUri,
						nonce: transaction.nonce,
						...(intent.resource === undefined ? {} : { resource: intent.resource }),
						callbackParams: callbackParamsOf(req),
						signal: AbortSignal.timeout(options.upstreamTimeoutMs),
						// Only the claims check 5 hands the Store, and none when it is not asked.
						identityClaims:
							options.identityLookup === "required" ? [...(connection.identityClaims ?? [])] : [],
					});
				} catch (error) {
					// Classified by what the error is, never its text (core's classifier).
					if (isFederationUpstreamOutage(error)) {
						// Not reached, or not in time: the outage the redirect says.
						log.outage(
							"federation_grant_callback_unavailable",
							{ ...context, reason: "upstream", step: "exchange" },
							error,
						);
						await fail("temporarily_unavailable");
					} else {
						// The upstream answered, and refused: its verdict, not an outage.
						log.degraded(
							"federation_grant_callback_exchange_refused",
							{ ...context, step: "exchange" },
							error,
						);
						await fail("upstream_error");
					}
					return;
				}
				const receivedAt = now().getTime();

				// 5. Account binding.
				const bound = await accountHolds(intent, connection, exchanged.upstream);
				if (!bound.holds) {
					if (bound.unanswered !== undefined) outage(bound.unanswered);
					await fail(bound.code, bound.reason);
					return;
				}

				// 6. Eligibility: a refresh token, and an access token this provider may
				// disclose, judged on lifetime and type here and on scope in step 7, so each
				// failure names its own check.
				const tokens = exchanged.tokens;
				const refreshToken =
					typeof tokens.refreshToken === "string" && tokens.refreshToken.length > 0
						? tokens.refreshToken
						: undefined;
				if (refreshToken === undefined) {
					await fail("refresh_token_absent");
					return;
				}
				// Parsed by RFC 6749 §3.3's grammar (`parseScopeTokens`): a tab separates two
				// scopes rather than forming one the user was never shown. Omitted means as
				// requested; named but empty is judged in step 7.
				const scopeText = tokens.scope;
				const granted =
					scopeText === undefined
						? [...transaction.consent.scopes]
						: [...parseScopeTokens(scopeText)];
				const lifetime =
					typeof tokens.expiresIn === "number" &&
					Number.isFinite(tokens.expiresIn) &&
					tokens.expiresAt instanceof Date &&
					!Number.isNaN(tokens.expiresAt.getTime())
						? tokens.expiresIn
						: null;
				if (typeof tokens.accessToken !== "string" || tokens.accessToken.length === 0) {
					await fail("upstream_token_ineligible");
					return;
				}
				// The scope is judged in step 7 and given here as consented, so this
				// can only refuse for the lifetime or the token type.
				const judgement = judgeUpstreamAccessToken({
					issuedLifetime: lifetime,
					scopes: granted,
					consentedScopes: granted,
					maxAccessTokenLifetime: connection.maxAccessTokenLifetime,
					tokenType: typeof tokens.tokenType === "string" ? tokens.tokenType : "",
				});
				if (!judgement.eligible || lifetime === null) {
					await fail("upstream_token_ineligible");
					return;
				}

				// 7. Scope containment: an upstream that granted more than the user
				// was shown is refused, because a token cannot be narrowed after
				// the fact. Omitted means as requested (RFC 6749 §5.1); present and
				// empty is not an answer.
				if (scopeText !== undefined && granted.length === 0) {
					await fail("upstream_token_ineligible");
					return;
				}
				const shown = new Set(transaction.consent.scopes);
				if (!granted.every((scope) => shown.has(scope))) {
					await fail("scope_exceeded");
					return;
				}

				// The mandatory re-read, immediately before the write: a subject-wide revocation
				// may have landed during the upstream work. This narrows an attacker-controlled
				// window (hold the upstream redirect, finish the callback later) to the gap
				// between these reads and the activation; closing it needs write fencing.
				const again = await sessionHolds(admission, req, claim, transaction);
				if (again !== "ok") {
					await fail(again === "unavailable" ? "temporarily_unavailable" : again);
					return;
				}
				let reasking: Omit<Unanswered, "error"> = { store: "revocation_boundary", step: "read" };
				try {
					const boundaryNow = await readBoundary(options.grantsBoundary, intent.subject);
					reasking = { store: "federation_grant", step: "is_current_intent" };
					if (
						!(await options.grantStore.isCurrentIntent(intent.grantId, intent.handle, now())) ||
						coveredByRevocationBoundary(
							transaction.consent.at,
							boundaryNow,
							options.revocationSkewMs,
						)
					) {
						await fail("grant_not_authorizable");
						return;
					}
				} catch (error) {
					outage({ ...reasking, error });
					await fail("temporarily_unavailable");
					return;
				}

				// 8. The guarded activation.
				const expiresAtMs = (tokens.expiresAt as Date).getTime();
				// When the token was obtained, on the adapter's clock, held inside the
				// window of the exchange — the retrieval's rule (retrieve.mts), so a
				// wild `expiresAt` can neither date a token in the future nor
				// lengthen its life.
				const obtainedAt = Math.min(Math.max(expiresAtMs - lifetime * 1000, calledAt), receivedAt);
				let written: Awaited<ReturnType<FederationGrantStore["activate"]>>;
				try {
					written = await options.grantStore.activate({
						grantId: intent.grantId,
						intentHandle: intent.handle,
						authorization: {
							identityRevision: intent.identityRevision,
							authorizationRevision: intent.authorizationRevision,
							upstream: { issuer: exchanged.upstream.issuer, subject: exchanged.upstream.subject },
							resource: intent.resource,
							scopes: granted,
							consent: {
								at: transaction.consent.at,
								sid: transaction.consent.sid,
								scopes: [...transaction.consent.scopes],
							},
							authorizedAt: now(),
							expiresAt: transaction.grantExpiresAt,
						},
						credentials: {
							refreshToken,
							accessToken: {
								value: tokens.accessToken,
								tokenType: tokens.tokenType as string,
								obtainedAt: new Date(obtainedAt),
								issuedLifetime: lifetime,
								scopes: granted,
							},
						},
						now: now(),
					});
				} catch (error) {
					outage({ store: "federation_grant", step: "activate", error });
					await fail("temporarily_unavailable");
					return;
				}
				if (!written.ok) {
					// The guard lost: superseded, revoked or expired in between. The
					// store says no more than that, and neither does this.
					await fail("grant_not_authorizable");
					return;
				}

				const grant = written.grant;
				if (intent.kind === "initial") {
					options.background.register(
						audit({
							type: "federation.grant.authorized",
							correlationId: flowId,
							grantId: grant.id,
							clientId: grant.clientId,
							subject: grant.subject,
							...federationGrantAuditMetadata(grant),
							outcome: bound.outcome,
						}).catch(() => undefined),
					);
				} else {
					options.background.register(
						audit({
							type: "federation.grant.reauthorized",
							correlationId: flowId,
							grantId: grant.id,
							clientId: grant.clientId,
							subject: grant.subject,
							...federationGrantAuditMetadata(grant),
							outcome: bound.outcome,
						}).catch(() => undefined),
					);
				}
				await finish();
				res.redirect(303, clientReturn(intent));
			} catch (error) {
				log.unexpected("callback", context, error);
				await fail("temporarily_unavailable");
			}
		}),
	);

	/**
	 * A renewal's backstop: the grant it would renew, compared with the subject's
	 * GRANTS boundary. A hit is revoked durably (the one failure here meant to
	 * change the record) and audited once, by whichever call wrote it.
	 */
	async function backstop(
		intent: FederationGrantIntent,
		boundary: Date | null,
		audit: ReturnType<typeof auditFor>,
		correlationId: string,
	): Promise<"clear" | "revoked" | { readonly unanswered: Unanswered }> {
		let step = "find";
		try {
			const grant = await options.grantStore.find(intent.grantId, now());
			if (grant === null || grant.status === "revoked") return "revoked";
			if (grant.status === "pending") return "clear";
			if (!coveredByRevocationBoundary(grant.consent.at, boundary, options.revocationSkewMs)) {
				return "clear";
			}
			step = "revoke";
			const written = await options.grantStore.revoke(grant.id, "backstop", now());
			if (written.ok) {
				options.background.register(
					audit({
						type: "federation.grant.revoked",
						correlationId,
						grantId: written.grant.id,
						clientId: written.grant.clientId,
						subject: written.grant.subject,
						...federationGrantAuditMetadata(written.grant),
						outcome: "backstop",
					}).catch(() => undefined),
				);
			}
			return "revoked";
		} catch (error) {
			return { unanswered: { store: "federation_grant", step, error } };
		}
	}

	/**
	 * Check 5. The verified issuer is the connection's; a renewal's upstream account
	 * is the one already on the grant; an expectation the client lodged is met; and,
	 * unless the deployment recorded that it cannot ask, the Store establishes who
	 * holds the upstream account: this user or nobody. Another user is a conflict.
	 * An answer that establishes neither also refuses: "cannot tell" is not "linked
	 * to nobody", and reading it so would let a pairwise `sub` through.
	 */
	async function accountHolds(
		intent: FederationGrantIntent,
		connection: FederationGrantAcquisitionConnection,
		upstream: { readonly issuer: string; readonly subject: string; readonly claims?: unknown },
	): Promise<AccountBinding> {
		const refused = (code: CallbackError, reason?: string): AccountBinding => ({
			holds: false,
			code,
			...(reason === undefined ? {} : { reason }),
		});
		/** Nothing could be established, and why: the redirect's `temporarily_unavailable`. */
		const unanswered = (at: Unanswered): AccountBinding => ({
			holds: false,
			code: "temporarily_unavailable",
			unanswered: at,
		});
		const LOOKUP = {
			store: "user_directory",
			step: "find_subject_by_federated_identity",
		} as const;
		if (upstream.issuer !== connection.upstreamIssuer) return refused("upstream_error");
		if (intent.upstreamSubject !== undefined && upstream.subject !== intent.upstreamSubject) {
			return refused("account_mismatch");
		}
		if (intent.kind === "reauthorization") {
			try {
				const grant = await options.grantStore.find(intent.grantId, now());
				const recorded = grant !== null && grant.status !== "pending" ? grant.upstream : undefined;
				if (
					recorded === undefined ||
					recorded.issuer !== upstream.issuer ||
					recorded.subject !== upstream.subject
				) {
					return refused("account_mismatch");
				}
			} catch (error) {
				return unanswered({ store: "federation_grant", step: "find", error });
			}
		}
		if (options.identityLookup === "unsupported") return { holds: true, outcome: "unsupported" };
		// Called through the repository, never detached: a Store written as a class needs
		// its `this`.
		const repository = options.userRepository;
		if (typeof repository?.findSubjectByFederatedIdentity !== "function") {
			// Boot refused this under "required"; a repository that lost the
			// method since is a composition fault an operator must hear about.
			return unanswered({
				...LOOKUP,
				error: new TypeError("the userRepository has no findSubjectByFederatedIdentity"),
			});
		}
		// Every claim the connection names, as the adapter verified it, or no question at
		// all: a lookup missing part of its evidence could answer "nobody". Only those
		// names reach the Store.
		const claims = requiredIdentityClaims(upstream.claims, connection.identityClaims ?? []);
		if (claims === undefined) {
			return refused("identity_unverifiable", "identity_claims_unavailable");
		}
		let answer: FederatedIdentityLookupResult | undefined;
		try {
			// The registration the identity was issued under — every part of it
			// the connection's configuration, the issuer already compared with the
			// verified one — so that a Store can place a `sub` that is pairwise
			// per registration.
			answer = lookupAnswer(
				await repository.findSubjectByFederatedIdentity({
					// The federation the exchange went through — the intent's, which
					// check 2 holds equal to the connection's: the name boot probed.
					...federationGrantIdentityRegistration({
						federation: intent.federation,
						upstreamIssuer: connection.upstreamIssuer,
						upstreamClientId: connection.upstreamClientId,
					}),
					sub: upstream.subject,
					claims,
				}),
			);
			if (answer === undefined) {
				throw new TypeError("the identity lookup answered something the port does not define");
			}
		} catch (error) {
			return unanswered({ ...LOOKUP, error });
		}
		switch (answer.kind) {
			case "linked":
				return answer.subject === intent.subject
					? { holds: true, outcome: "required/linked" }
					: refused("identity_conflict");
			case "unlinked":
				return { holds: true, outcome: "required/unlinked" };
			case "indeterminate":
				return refused("identity_unverifiable", answer.reason);
		}
	}

	// Everything else under the mount: plain, not the JSON router's 404.
	router.use((_req, res) => plain(res, 404, "Not found."));
	router.use(unexpectedErrors(options.logger, "federation_grants_browser"));
	return router;
}

/**
 * Check 5's verdict. When it holds, `outcome` is what the grant's event
 * records: which answer let it through, or that the deployment does not ask.
 */
type AccountBinding =
	| {
			readonly holds: true;
			readonly outcome: "required/linked" | "required/unlinked" | "unsupported";
	  }
	| {
			readonly holds: false;
			readonly code: CallbackError;
			readonly reason?: string;
			/** When nothing could be established: what could not answer, for the one line. */
			readonly unanswered?: Unanswered;
	  };

/**
 * The named claims out of what the adapter answered, as a fresh object, or
 * `undefined` if any is not an own, non-empty string.
 */
function requiredIdentityClaims(
	answered: unknown,
	names: readonly string[],
): Readonly<Record<string, string>> | undefined {
	const claims: Record<string, string> = {};
	if (names.length === 0) return claims;
	// An array is an object, and `"0"` a legal claim name.
	if (typeof answered !== "object" || answered === null || Array.isArray(answered)) {
		return undefined;
	}
	for (const name of names) {
		if (!Object.hasOwn(answered, name)) return undefined;
		const value = (answered as Record<string, unknown>)[name];
		if (typeof value !== "string" || value.length === 0) return undefined;
		claims[name] = value;
	}
	return claims;
}

/**
 * A lookup's answer if it is one the port defines, and `undefined` otherwise.
 * Recognised positively: any other shape (a bare string, `null`) must not fall
 * through to an outcome that lets a grant through.
 */
function lookupAnswer(value: unknown): FederatedIdentityLookupResult | undefined {
	if (typeof value !== "object" || value === null) return undefined;
	const answer = value as {
		readonly kind?: unknown;
		readonly subject?: unknown;
		readonly reason?: unknown;
	};
	switch (answer.kind) {
		case "linked":
			return typeof answer.subject === "string" && answer.subject.length > 0
				? { kind: "linked", subject: answer.subject }
				: undefined;
		case "unlinked":
			return { kind: "unlinked" };
		case "indeterminate":
			return answer.reason === "registration_not_covered" ||
				answer.reason === "identity_not_resolvable"
				? { kind: "indeterminate", reason: answer.reason }
				: undefined;
		default:
			return undefined;
	}
}

/** A boundary, or a refusal: an answer that is neither a date nor `null` is not "nothing revoked". */
async function readBoundary(
	read: (subject: string) => Promise<Date | null>,
	subject: string,
): Promise<Date | null> {
	const boundary = await read(subject);
	if (boundary !== null && !(boundary instanceof Date && !Number.isNaN(boundary.getTime()))) {
		throw new TypeError("the boundary is neither a date nor null");
	}
	return boundary;
}

/** Whether the connection is still what the intent was lodged against. */
function pinned(
	connection: FederationGrantAcquisitionConnection | undefined,
	intent: FederationGrantIntent,
): connection is FederationGrantAcquisitionConnection {
	return (
		connection !== undefined &&
		// Not in either revision, and still pinned: a connection re-pointed onto another
		// federation entry mid-flow would have check 5 ask about a registration boot
		// never probed.
		connection.federation === intent.federation &&
		federationGrantIdentityRevision(connection) === intent.identityRevision &&
		federationGrantAuthorizationRevision(connection) === intent.authorizationRevision &&
		connection.callbackUri === intent.callbackUri
	);
}

/** What a disabled deployment mounts here: a plain 404 that names no feature. */
export function createDisabledFederationGrantBrowserRouter(): Router {
	const router = express.Router();
	router.use(noStoreNoReferrer);
	router.use((_req, res) => plain(res, 404, "Not found."));
	return router;
}
