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
 * Connect is cross-site by construction, so it skips the login flow's
 * `Sec-Fetch-Site` check and `session.csrf.trustedOrigins` is not widened to
 * client origins; consent is its CSRF defence. That holds only while connect
 * never approves or creates an upstream transaction, every grant and renewal
 * (first-party clients too) goes through consent, the answer needs the
 * challenge AND the exact session binding, the consent data is never readable
 * cross-origin with credentials, the challenge never leaks via a referrer
 * (`Referrer-Policy: no-referrer` on every response), and the answer re-admits
 * the session. Making consent skippable is a redesign of this exemption.
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

import { randomBytes } from "node:crypto";
import {
	ADMISSION_ACTIONS,
	type AdmissionAction,
	type AdmissionDeps,
	type AuditSink,
	admitSession,
	type ClientRepository,
	type CookieCarrier,
	checkCanonicalIssuer,
	checkResolver,
	checkWithFailMode,
	cookieClaim,
	coveredByRevocationBoundary,
	describeAdmissionOutage,
	describeIssuerRejection,
	type FederatedIdentityLookupResult,
	type FederationGrantAcquisitionConnection,
	type FederationGrantBrowserBinding,
	type FederationGrantConnectTransaction,
	type FederationGrantIntent,
	type FederationGrantIntentStore,
	type FederationGrantStore,
	federationGrantAllowlist,
	federationGrantAuditMetadata,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
	isFederationUpstreamOutage,
	judgeUpstreamAccessToken,
	type Logger,
	type LoginEntry,
	parseScopeTokens,
	type RateLimiter,
	recordAuditEvent,
	type SessionClaim,
	type SessionRequirementResolver,
	type SubjectRevocation,
	type SupportsDelegatedAuthorization,
	type UserRepository,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import express, { type Request, type RequestHandler, type Response, type Router } from "express";
import { federationGrantIdentityRegistration } from "./acquisitionSettings.mjs";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "./audit.mjs";
import type { FederationGrantBackground } from "./background.mjs";
import { federationGrantConnectUri } from "./lodgeRoute.mjs";
import { createFederationGrantLog, type LogFields } from "./log.mjs";
import { createRequestIdMiddleware, requestIdOf } from "./requestId.mjs";
import { parserRefusals, unexpectedErrors } from "./routes.mjs";

/** Where this router is mounted. */
export const FEDERATION_GRANTS_BROWSER_MOUNT_PATH = "/session/federation-grants";

/**
 * What the connect flow needs of a federation: the authorization URL the consent
 * answer sends the user to, and the callback's code exchange. Refresh is the token
 * route's business.
 */
export type FederationGrantDelegatedAuthorizer = Pick<
	SupportsDelegatedAuthorization,
	"buildDelegatedAuthorizationUrl" | "exchangeDelegatedCode"
>;

export interface FederationGrantBrowserRouterOptions {
	readonly intentStore: FederationGrantIntentStore;
	readonly grantStore: FederationGrantStore;
	readonly clientRepository: ClientRepository;
	/** The durable sessions behind the cookie, which admission re-reads at every step. */
	readonly userSessionStore: UserSessionStore;
	/**
	 * Where admission reads the subject's SESSIONS boundary, which a session must have
	 * authenticated after. The grants boundary is `grantsBoundary`.
	 */
	readonly subjectRevocation: SubjectRevocation;
	/**
	 * The `sessionRequirementResolver` the boot planner built (`resolverForTests` in
	 * tests): the session requirements admission asks. Admission refuses any other
	 * object.
	 */
	readonly requirements: SessionRequirementResolver;
	/** The clock-skew allowance the GRANTS boundary is compared with. */
	readonly revocationSkewMs: number;
	readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
	/** The federation's delegated authorizer, or `undefined` when it has none. */
	readonly authorizerFor: (federation: string) => FederationGrantDelegatedAuthorizer | undefined;
	/** `federationGrants.consent.url`: a path, or an absolute URL on the provider's origin. */
	readonly consentUrl: string;
	/**
	 * The login page a browser that is not signed in is sent to, and its
	 * `redirect_to` protocol: the session module's `loginEntry` slot.
	 */
	readonly login: Pick<LoginEntry, "urlFor">;
	/** `oauth.jwt.issuer`, held to core's `checkCanonicalIssuer`: every URL this router builds is built on it. */
	readonly issuer: string;
	/** The browser budget; its own `failMode` is the outage policy. */
	readonly rateLimiter: RateLimiter;
	readonly background: FederationGrantBackground;
	/**
	 * The subject's GRANTS boundary: what the callback's backstop and re-read
	 * compare a consent with.
	 */
	readonly grantsBoundary: (subject: string) => Promise<Date | null>;
	/** Callback check 5: whether the Store is asked who holds the upstream account. */
	readonly identityLookup: "required" | "unsupported";
	/** The port's own signature, not a copy of it, so the two cannot drift apart. */
	readonly userRepository?: Pick<UserRepository, "findSubjectByFederatedIdentity">;
	/** Milliseconds: where the code exchange is aborted (`upstreamHardTimeoutMs`). */
	readonly upstreamTimeoutMs: number;
	readonly now?: () => Date;
	/** 256 random bits, base64url. A seam for tests. */
	readonly randomId?: () => string;
	readonly auditSink?: AuditSink;
	readonly logger?: Logger;
}

/** The limiter tag; a budget of its own, apart from the JSON routes'. */
export const FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX = "federation_grants_browser";

/**
 * One answer for every challenge with nothing behind it — answered, expired,
 * never issued, issued to another browser — so the response does not say
 * which. The sibling's wording, for the page that already handles it.
 */
const NO_PENDING =
	"no pending consent for this challenge: it was answered, has expired, or was not issued to this session; start again";

const BODY_LIMIT = "8kb";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

const noStoreNoReferrer: RequestHandler = (_req, res, next) => {
	res.set("Cache-Control", "no-store");
	res.set("Pragma", "no-cache");
	// The challenge and the handle travel in URLs; neither may leave in a
	// Referer header to whatever the page links to.
	res.set("Referrer-Policy", "no-referrer");
	next();
};

/** A navigation's refusal: plain text, never a JSON body a user would see raw. */
const plain = (res: Response, status: number, message: string): void => {
	res.status(status).type("text/plain").send(message);
};

/** The page's refusal, in `/oauth/consent`'s shape. */
const jsonError = (res: Response, status: number, error: string, description: string): void => {
	res.status(status).json({ error, error_description: description });
};

const single = (value: unknown): string | undefined =>
	typeof value === "string" && value.length > 0 ? value : undefined;

/** The express session's own id: one half of the browser binding, the durable `sid` the other. */
const sessionIdOf = (req: Request): string | undefined =>
	single((req as { sessionID?: unknown }).sessionID);

/**
 * The cookie's claim, core's one reading of it (`cookieClaim`). `req.session`
 * is the session middleware's field, which this package does not type.
 */
const claimOf = (req: Request): SessionClaim => cookieClaim(req as CookieCarrier);

/** A browser prefetching a link has not asked for it: nothing is parked on its behalf. */
const isPrefetch = (req: Request): boolean => {
	const purpose = `${req.get("sec-purpose") ?? ""} ${req.get("purpose") ?? ""}`.toLowerCase();
	return purpose.includes("prefetch") || purpose.includes("prerender");
};

// ---------------------------------------------------------------------------
// The judgement both halves share
// ---------------------------------------------------------------------------

/**
 * What could not answer, for the one line an outage writes: the store (or
 * `client`, the client registry, which core's own line reports), what it was
 * asked, and what it threw. The session's part is admission's, which writes
 * its own line.
 */
interface Unanswered {
	readonly store:
		| "federation_grant"
		| "federation_grant_intent"
		| "revocation_boundary"
		| "user_directory"
		| "client";
	readonly step: string;
	readonly error: unknown;
}

type Judgement =
	| { readonly ok: true; readonly binding: FederationGrantBrowserBinding }
	| {
			readonly ok: false;
			readonly status: number;
			/** A fixed identifier: what the audit carries, and what a navigation names. */
			readonly reason:
				| "subject_mismatch"
				| "reauthentication_required"
				| "stale"
				| "connection_not_permitted"
				| "connection_changed";
	  }
	| {
			readonly ok: false;
			readonly status: 503;
			readonly reason: "unavailable";
			/**
			 * What could not answer: the caller logs it, once. Absent when it was
			 * the session's part, whose line admission wrote.
			 */
			readonly unanswered?: Unanswered;
			/**
			 * When it was the session's part: the store admission named, described as core's
			 * `describeAdmissionOutage` does.
			 */
			readonly admissionStore?: string;
	  };

/** The admission action of each browser step, each graded `use`. */
const CONNECT: AdmissionAction = ADMISSION_ACTIONS["federation_grants.connect"];
const CONSENT: AdmissionAction = ADMISSION_ACTIONS["federation_grants.consent"];
const CALLBACK: AdmissionAction = ADMISSION_ACTIONS["federation_grants.callback"];

/** The browser half selects no `acr`: nothing asks for one here. */
const NO_ACR_TABLE: AdmissionDeps["acrTable"] = Object.freeze({});

/**
 * The session's part of a judgement: the live record; `null` for any session a new
 * login is the remedy for (gone, expired, another subject's, covered by the
 * sessions boundary, or refused by a requirement, `step_up` included); or an
 * outage admission has already logged, with the store it named.
 */
async function admittedSession(
	deps: AdmissionDeps,
	claim: SessionClaim,
	action: AdmissionAction,
): Promise<UserSession | null | { readonly unavailable: string }> {
	const admission = await admitSession(deps, { claim, action });
	if (admission.outcome === "unavailable") return { unavailable: admission.store };
	return admission.outcome === "admitted" ? admission.session : null;
}

/** Whether the session's part was an outage, rather than a record or a refusal. */
const isAdmissionOutage = (
	part: UserSession | null | { readonly unavailable: string },
): part is { readonly unavailable: string } => part !== null && "unavailable" in part;

/**
 * Whether THIS browser may go on with THIS intent now: the cookie names the
 * intent's subject, admission admits its session as `action`, the intent is still
 * the grant's current one, the client may still use the connection, and the
 * connection is unchanged since lodging. Asked at every step, so a revocation,
 * renewal or configuration change mid-flow stops a flow that has not finished.
 */
async function judge(
	options: FederationGrantBrowserRouterOptions,
	admission: AdmissionDeps,
	req: Request,
	claim: SessionClaim,
	action: AdmissionAction,
	intent: FederationGrantIntent,
	now: () => Date,
): Promise<Judgement> {
	if (claim.subject !== intent.subject) {
		return { ok: false, status: 403, reason: "subject_mismatch" };
	}
	const sessionId = sessionIdOf(req);
	if (sessionId === undefined) {
		return { ok: false, status: 403, reason: "reauthentication_required" };
	}

	// A session that authenticated at or before the sessions boundary may not mint a
	// consent dated after it; `authTime` never changes, so signing in again is the
	// remedy, and the distinct error lets the page say so.
	const session = await admittedSession(admission, claim, action);
	if (isAdmissionOutage(session)) {
		return { ok: false, status: 503, reason: "unavailable", admissionStore: session.unavailable };
	}
	if (session === null) return { ok: false, status: 403, reason: "reauthentication_required" };

	// Which question is being asked, so that a failure names what could not answer.
	let asking: Omit<Unanswered, "error"> = { store: "federation_grant", step: "is_current_intent" };
	try {
		if (!(await options.grantStore.isCurrentIntent(intent.grantId, intent.handle, now()))) {
			return { ok: false, status: 400, reason: "stale" };
		}
		asking = { store: "client", step: "find" };
		const client = await options.clientRepository.findById(intent.clientId);
		// Read as a list or as nothing (`federationGrantAllowlist`): a repository
		// answering a string would otherwise match by substring.
		const allowed = federationGrantAllowlist(
			(client as { allowedFederationGrantConnections?: unknown } | null)
				?.allowedFederationGrantConnections,
		);
		if (client === null || !allowed.includes(intent.connection)) {
			return { ok: false, status: 403, reason: "connection_not_permitted" };
		}
	} catch (error) {
		// Fails closed: a pointer or a client that cannot be read is not a yes.
		return { ok: false, status: 503, reason: "unavailable", unanswered: { ...asking, error } };
	}

	const connection = options.connections.get(intent.connection);
	if (
		connection === undefined ||
		// The revisions pin the issuer and client, not the federation's name; boot
		// probed the Store under the name the connection has NOW.
		connection.federation !== intent.federation ||
		federationGrantIdentityRevision(connection) !== intent.identityRevision ||
		federationGrantAuthorizationRevision(connection) !== intent.authorizationRevision ||
		connection.callbackUri !== intent.callbackUri
	) {
		// The user would be shown one thing and the upstream asked for another.
		return { ok: false, status: 400, reason: "connection_changed" };
	}
	return { ok: true, binding: { sessionId, sid: session.sid, subject: session.sub } };
}

/** The consent page's URL with the challenge on it. */
function consentLocation(consentUrl: string, issuer: string, challenge: string): string {
	const url = new URL(consentUrl, issuer);
	url.searchParams.set("challenge", challenge);
	// Always absolute on the issuer: a normalised path would turn
	// `/.//evil.example/consent` into a protocol-relative `//evil.example/consent`
	// Location carrying the challenge to another host. Boot refuses such a path too.
	return url.href;
}

/** Where a declined flow ends: the client's own URI, with what it needs and nothing else. */
function clientReturn(intent: FederationGrantIntent, error?: string): string {
	const url = new URL(intent.redirectUri);
	url.searchParams.set("grant_id", intent.grantId);
	url.searchParams.set("state", intent.clientState);
	if (error !== undefined) url.searchParams.set("error", error);
	return url.href;
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

export function createFederationGrantBrowserRouter(
	options: FederationGrantBrowserRouterOptions,
): Router {
	// Refused where the composition is assembled, not answered 500 on every
	// request: a missing resolver, or one the planner did not build.
	const requirements = checkResolver(options.requirements, "createFederationGrantBrowserRouter");
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
	const now = options.now ?? (() => new Date());
	const randomId = options.randomId ?? (() => randomBytes(32).toString("base64url"));
	const log = createFederationGrantLog(options.logger);
	/**
	 * The deployment's audit sink with every write registered with the drain, so a
	 * shutdown also waits for the events admission records.
	 */
	const auditSink = options.auditSink;
	const drainedAuditSink: AuditSink | undefined =
		auditSink === undefined
			? undefined
			: {
					kind: auditSink.kind,
					record: (event) => {
						// Through core's `recordAuditEvent`, the one writer of a sink.
						const written = recordAuditEvent(auditSink, event);
						options.background.register(written.catch(() => undefined));
						return written;
					},
				};
	/**
	 * Admission's dependencies for one request: its logger is bound to the flow's
	 * grant, the request's correlation id and (at the consent) its method, so an
	 * outage line admission writes carries them too.
	 */
	const admissionFor = (flow: LogFields): AdmissionDeps => ({
		userSessionStore: options.userSessionStore,
		subjectRevocation,
		requirements,
		acrTable: NO_ACR_TABLE,
		logger: log.bound(flow),
		auditSink: drainedAuditSink,
		now,
	});
	const router = express.Router();

	/**
	 * A judgement that could not be made, as one line: the client registry as
	 * core's `client_repository_unavailable` with this route as its site, any
	 * other store as the route's own outage.
	 */
	const judgementUnavailable = (
		route: "connect" | "consent",
		fields: Readonly<Record<string, string | undefined>>,
		intent: FederationGrantIntent,
		unanswered: Unanswered,
	): void => {
		if (unanswered.store === "client") {
			log.clientRepositoryUnavailable(
				`federation_grant_${route}`,
				intent.clientId,
				unanswered.error,
			);
			return;
		}
		log.outage(
			`federation_grant_${route}_unavailable`,
			{ ...fields, reason: "storage", store: unanswered.store, step: unanswered.step },
			unanswered.error,
		);
	};

	const auditFor = (req: Request) =>
		createFederationGrantAuditBridge({
			...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
			...(req.ip === undefined ? {} : { ip: req.ip }),
			...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
			operation: "connect",
			now,
		});

	/** `federation.grant.authorization_failed`, with only what is established. */
	const failed = (req: Request, res: Response, outcome: string, intent?: FederationGrantIntent) => {
		options.background.register(
			auditFor(req)(
				routeDeniedEvent({
					type: "federation.grant.authorization_failed",
					// The FLOW's id once its intent is known — the one the lodging
					// request carried, so that every event of one flow correlates.
					// Before that there is only this request's own.
					correlationId: intent?.correlationId ?? requestIdOf(res),
					// An early failure has no grant to name, and none is invented.
					grantId: intent?.grantId ?? "",
					outcome,
					...(intent === undefined
						? {}
						: {
								clientId: intent.clientId,
								subject: intent.subject,
								connection: intent.connection,
							}),
				}),
			).catch(() => undefined),
		);
	};

	/** The browser budget: the outage policy is core's, the rendering is the transport's. */
	const throttle =
		(render: (res: Response, status: number) => void): RequestHandler =>
		async (req, res, next) => {
			const ip = req.ip ?? "unknown";
			// The deployment's own logger and audit sink: a limiter outage here
			// is logged and audited as on every other throttled route.
			const outcome = await checkWithFailMode(
				{
					limiter: options.rateLimiter,
					tag: FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX,
					...(options.logger === undefined ? {} : { logger: options.logger }),
					...(options.auditSink === undefined ? {} : { auditSink: options.auditSink }),
				},
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
		admitted(shuttingDownPlain, async (req, res) => {
			try {
				// A prefetch is not the user asking: nothing is parked for it.
				if (isPrefetch(req)) {
					res.status(204).end();
					return;
				}
				const handle = single(req.query.request);
				if (handle === undefined) {
					plain(res, 400, "This link is not valid.");
					return;
				}
				let intent: FederationGrantIntent | null;
				try {
					intent = await options.intentStore.getIntent(handle, now());
				} catch (error) {
					log.outage(
						"federation_grant_connect_unavailable",
						{
							correlationId: requestIdOf(res),
							reason: "storage",
							store: "federation_grant_intent",
							step: "get_intent",
						},
						error,
					);
					plain(res, 503, "Temporarily unavailable.");
					return;
				}
				if (intent === null) {
					failed(req, res, "stale");
					plain(res, 400, "This link has expired or has already been used. Start again.");
					return;
				}
				// Not signed in: sign in and come back to exactly this link (its handle only).
				// Read from the claim before the session is asked anything, as `/authorize` does.
				const claim = claimOf(req);
				if (!claim.authenticated) {
					res.redirect(
						303,
						options.login.urlFor(federationGrantConnectUri(options.issuer, handle)),
					);
					return;
				}
				const judged = await judge(
					options,
					admissionFor({ grantId: intent.grantId, correlationId: requestIdOf(res) }),
					req,
					claim,
					CONNECT,
					intent,
					now,
				);
				if (!judged.ok) {
					if (judged.reason === "unavailable" && judged.unanswered !== undefined) {
						judgementUnavailable(
							"connect",
							{ grantId: intent.grantId, correlationId: requestIdOf(res) },
							intent,
							judged.unanswered,
						);
					}
					failed(req, res, judged.reason, intent);
					plain(res, judged.status, messageFor(judged.reason));
					return;
				}
				let parked: Awaited<ReturnType<FederationGrantIntentStore["parkConsent"]>>;
				try {
					parked = await options.intentStore.parkConsent({
						handle,
						challenge: randomId(),
						binding: judged.binding,
						now: now(),
					});
				} catch (error) {
					log.outage(
						"federation_grant_connect_unavailable",
						{
							grantId: intent.grantId,
							correlationId: requestIdOf(res),
							reason: "storage",
							store: "federation_grant_intent",
							step: "park_consent",
						},
						error,
					);
					plain(res, 503, "Temporarily unavailable.");
					return;
				}
				if (parked === null) {
					plain(res, 400, "This link has expired or has already been used. Start again.");
					return;
				}
				res.redirect(303, consentLocation(options.consentUrl, options.issuer, parked.challenge));
			} catch (error) {
				log.unexpected("connect", { correlationId: requestIdOf(res) }, error);
				plain(res, 500, "Something went wrong.");
			}
		}),
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
				// Belt to the challenge's braces: a page on this origin sends
				// `same-origin`, and a navigation from nowhere sends `none`.
				const site = req.get("sec-fetch-site");
				if (site !== undefined && site !== "same-origin" && site !== "none") {
					jsonError(res, 403, "invalid_request", "cross-site answer refused");
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
	 * Check 3, asked before the exchange and again before activation with the same
	 * claim: the same express session and durable session the flow started in,
	 * admitted as the callback. An outage is `"unavailable"`, already logged by
	 * admission.
	 */
	async function sessionHolds(
		admission: AdmissionDeps,
		req: Request,
		claim: SessionClaim,
		transaction: FederationGrantConnectTransaction,
	): Promise<"ok" | "reauthentication_required" | "account_mismatch" | "unavailable"> {
		const { binding, intent } = transaction;
		if (!claim.authenticated) return "reauthentication_required";
		if (claim.subject !== intent.subject || binding.subject !== intent.subject) {
			return "account_mismatch";
		}
		if (sessionIdOf(req) !== binding.sessionId || claim.sid !== binding.sid) {
			return "reauthentication_required";
		}
		const session = await admittedSession(admission, claim, CALLBACK);
		if (isAdmissionOutage(session)) return "unavailable";
		return session === null ? "reauthentication_required" : "ok";
	}

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
 * What a failed callback sends back to the client, and nothing else.
 * `identity_unverifiable` is not `temporarily_unavailable`: asking again will not
 * change it.
 */
type CallbackError =
	| "access_denied"
	| "reauthentication_required"
	| "account_mismatch"
	| "identity_conflict"
	| "identity_unverifiable"
	| "refresh_token_absent"
	| "upstream_token_ineligible"
	| "scope_exceeded"
	| "upstream_error"
	| "temporarily_unavailable"
	| "grant_not_authorizable";

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

/**
 * The rest of the callback's parameters, string values only, without `code`
 * and `state` — which the flow binds itself — exactly as `exchangeCode` takes
 * them, so an adapter forwards `iss` (RFC 9207) the one way it knows.
 */
function callbackParamsOf(req: Request): Readonly<Record<string, string>> {
	const params: Record<string, string> = {};
	for (const [key, value] of Object.entries(req.query)) {
		if (key === "code" || key === "state") continue;
		if (typeof value === "string") params[key] = value;
	}
	return params;
}

function messageFor(reason: Exclude<Judgement, { ok: true }>["reason"]): string {
	switch (reason) {
		case "subject_mismatch":
			return "This request was made for another account.";
		case "reauthentication_required":
			return "Sign in again to continue.";
		case "stale":
			return "This request was replaced by a newer one. Start again.";
		case "connection_not_permitted":
			return "This application may no longer use this connection.";
		case "connection_changed":
			return "The connection has changed since this request was made. Start again.";
		case "unavailable":
			return "Temporarily unavailable.";
	}
}

/** What a disabled deployment mounts here: a plain 404 that names no feature. */
export function createDisabledFederationGrantBrowserRouter(): Router {
	const router = express.Router();
	router.use(noStoreNoReferrer);
	router.use((_req, res) => plain(res, 404, "Not found."));
	return router;
}
