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
 * The browser half of acquisition (#593, D7, D8, slice 6), mounted at
 * `/session/federation-grants`: the connect start a client sends the user to,
 * and the consent the deployment's page reads and answers.
 *
 * ## Two transports, because two different things read the responses
 *
 * - **`GET /connect` is a navigation.** Nothing but a browser sees it, so it
 *   answers with redirects and plain text — never a JSON body, which a user
 *   would see raw.
 * - **`GET` and `POST /consent` are the deployment page's contract**, and they
 *   mirror `/oauth/consent` exactly, because that page already implements the
 *   sibling: JSON page data, JSON errors, `401 login_required` for a session
 *   that died, one indistinguishable answer for every challenge with nothing
 *   behind it, and `303` for both success paths of the `POST`.
 *
 * Neither inherits the JSON router's client authentication, its 404, or its
 * throttle's body: this router has its own, and the regression test mounts the
 * real one to see every exit's representation.
 *
 * ## Why connect needs no request-origin check, and what that depends on
 *
 * `GET /connect` is a cross-site navigation by construction — a client's site
 * sends the browser here — so it does not apply the login flow's
 * `Sec-Fetch-Site` refusal, and `session.csrf.trustedOrigins` is not widened to
 * client origins. That is sound because holding a handle authorizes nothing:
 * an activation needs an explicit consent answer carrying a fresh 256-bit
 * challenge issued to THIS browser session, read by a same-origin page. An
 * attacker who lodged the intent knows the handle; it cannot learn or choose
 * the victim's challenge. So the exemption holds only while:
 *
 * - connect never approves, and never creates an upstream transaction;
 * - every grant and renewal goes through consent — first-party clients too;
 * - the answer requires the challenge AND the exact session binding;
 * - the consent data is never readable cross-origin with credentials;
 * - the challenge does not leak through a referrer (`Referrer-Policy:
 *   no-referrer` is set on every response here);
 * - the answer re-checks the session's liveness and the sessions boundary.
 *
 * Removing mandatory consent later is a redesign of this exemption, not a UI
 * preference. The `POST` additionally refuses explicit cross-site fetch
 * metadata, which costs a legitimate page nothing.
 */

import { randomBytes } from "node:crypto";
import {
	type AuditSink,
	type ClientRepository,
	checkWithFailMode,
	coveredByRevocationBoundary,
	type FederationGrantAcquisitionConnection,
	type FederationGrantBrowserBinding,
	type FederationGrantConnectTransaction,
	type FederationGrantIntent,
	type FederationGrantIntentStore,
	type FederationGrantStore,
	federationGrantAuditMetadata,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
	judgeUpstreamAccessToken,
	type Logger,
	type RateLimiter,
	type RateLimitFailMode,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { SupportsDelegatedAuthorization } from "@o3co/auth-provider-session";
import express, {
	type ErrorRequestHandler,
	type Request,
	type RequestHandler,
	type Response,
	type Router,
} from "express";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "./audit.mjs";
import type { FederationGrantBackground } from "./background.mjs";
import { federationGrantConnectUri } from "./lodgeRoute.mjs";
import { createSanitizedReporter } from "./report.mjs";
import { createRequestIdMiddleware, requestIdOf } from "./requestId.mjs";

/** Where this router is mounted. */
export const FEDERATION_GRANTS_BROWSER_MOUNT_PATH = "/session/federation-grants";

/**
 * What the connect flow needs of a federation (D17): the authorization URL the
 * consent answer sends the user to, and the exchange the callback makes. The
 * capability's refresh is the token route's business, not this router's.
 */
export type FederationGrantDelegatedAuthorizer = Pick<
	SupportsDelegatedAuthorization,
	"buildDelegatedAuthorizationUrl" | "exchangeDelegatedCode"
>;

export interface FederationGrantBrowserRouterOptions {
	readonly intentStore: FederationGrantIntentStore;
	readonly grantStore: FederationGrantStore;
	readonly clientRepository: ClientRepository;
	/** The durable sessions behind the cookie, re-read at every step. */
	readonly userSessionStore: UserSessionStore;
	/** The subject's SESSIONS boundary (D13): a session must have authenticated after it. */
	readonly sessionsBoundary: (subject: string) => Promise<Date | null>;
	readonly revocationSkewMs: number;
	readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
	/** The federation's delegated authorizer, or `undefined` when it has none. */
	readonly authorizerFor: (federation: string) => FederationGrantDelegatedAuthorizer | undefined;
	/** `federationGrants.consent.url`: a path, or an absolute URL on the provider's origin. */
	readonly consentUrl: string;
	/** `endpoints.login.url`, read per request as `/authorize` reads it. */
	readonly loginUrl: () => string;
	/** `oauth.jwt.issuer`: every URL this router builds is built on it. */
	readonly issuer: string;
	readonly rateLimiter: RateLimiter;
	readonly failMode: RateLimitFailMode;
	readonly background: FederationGrantBackground;
	/** The subject's GRANTS boundary (D13): what the callback's backstop and re-read compare a consent with. */
	readonly grantsBoundary: (subject: string) => Promise<Date | null>;
	/** D7 check 5: whether an upstream account linked to another local user is refused. */
	readonly identityLookup: "required" | "unsupported";
	readonly userRepository?: {
		readonly findSubjectByFederatedIdentity?: (identity: {
			readonly provider: string;
			readonly sub: string;
		}) => Promise<string | null>;
	};
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
	"no pending consent for this challenge — it was answered, has expired, or was not issued to this session; start again";

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

const sessionIdOf = (req: Request): string | undefined =>
	single((req as { sessionID?: unknown }).sessionID);

const sessionOf = (req: Request) =>
	(req as { session?: { isAuthenticated?: unknown; user?: { id?: unknown }; sid?: unknown } })
		.session;

const authenticated = (req: Request): boolean => sessionOf(req)?.isAuthenticated === true;
const subjectOf = (req: Request): string | undefined => single(sessionOf(req)?.user?.id);
const durableSidOf = (req: Request): string | undefined => single(sessionOf(req)?.sid);

/** A browser prefetching a link has not asked for it: nothing is parked on its behalf. */
const isPrefetch = (req: Request): boolean => {
	const purpose = `${req.get("sec-purpose") ?? ""} ${req.get("purpose") ?? ""}`.toLowerCase();
	return purpose.includes("prefetch") || purpose.includes("prerender");
};

// ---------------------------------------------------------------------------
// The judgement both halves share
// ---------------------------------------------------------------------------

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
				| "connection_changed"
				| "unavailable";
	  };

/**
 * Whether THIS browser may go on with THIS intent now: the session is the
 * intent's subject's, still live, authenticated after the sessions boundary;
 * the intent is still the grant's current one; the client may still use the
 * connection; and the connection is still what the intent was lodged against.
 *
 * Asked at the start, when the page reads the question, and when it answers:
 * a session revoked, a grant renewed elsewhere, or a configuration changed in
 * between must stop a flow that has not finished.
 */
async function judge(
	options: FederationGrantBrowserRouterOptions,
	req: Request,
	intent: FederationGrantIntent,
	now: () => Date,
): Promise<Judgement> {
	const subject = subjectOf(req);
	if (subject !== intent.subject) return { ok: false, status: 403, reason: "subject_mismatch" };
	const sessionId = sessionIdOf(req);
	const sid = durableSidOf(req);
	if (sessionId === undefined || sid === undefined) {
		return { ok: false, status: 403, reason: "reauthentication_required" };
	}

	try {
		const durable = await options.userSessionStore.get(sid);
		const at = now();
		if (
			durable === null ||
			durable === undefined ||
			durable.sub !== subject ||
			!(at.getTime() < durable.expiresAt.getTime())
		) {
			return { ok: false, status: 403, reason: "reauthentication_required" };
		}
		const boundary = await options.sessionsBoundary(subject);
		if (boundary !== null && !(boundary instanceof Date && !Number.isNaN(boundary.getTime()))) {
			throw new TypeError("the sessions boundary is neither a date nor null");
		}
		// A session that authenticated at or before the subject's sessions
		// boundary may not mint a consent dated after it: `authTime` never
		// changes, so signing in again is the remedy, and the distinct error
		// lets the page say so. D13's comparison, D13's allowance.
		if (coveredByRevocationBoundary(durable.authTime, boundary, options.revocationSkewMs)) {
			return { ok: false, status: 403, reason: "reauthentication_required" };
		}
		if (!(await options.grantStore.isCurrentIntent(intent.grantId, intent.handle, now()))) {
			return { ok: false, status: 400, reason: "stale" };
		}
		const client = await options.clientRepository.findById(intent.clientId);
		const allowed =
			(client as { allowedFederationGrantConnections?: readonly string[] } | null)
				?.allowedFederationGrantConnections ?? [];
		if (client === null || !allowed.includes(intent.connection)) {
			return { ok: false, status: 403, reason: "connection_not_permitted" };
		}
	} catch {
		// Fails closed: a session, a boundary, a pointer or a client that cannot
		// be read is not a yes.
		return { ok: false, status: 503, reason: "unavailable" };
	}

	const connection = options.connections.get(intent.connection);
	if (
		connection === undefined ||
		federationGrantIdentityRevision(connection) !== intent.identityRevision ||
		federationGrantAuthorizationRevision(connection) !== intent.authorizationRevision ||
		connection.callbackUri !== intent.callbackUri
	) {
		// The user would be shown one thing and the upstream asked for another.
		return { ok: false, status: 400, reason: "connection_changed" };
	}
	return { ok: true, binding: { sessionId, sid, subject } };
}

/** The consent page's URL with the challenge on it. */
function consentLocation(consentUrl: string, issuer: string, challenge: string): string {
	const url = new URL(consentUrl, issuer);
	url.searchParams.set("challenge", challenge);
	// A path stays a path: the page is on this origin, and the browser resolves it.
	return consentUrl.startsWith("/") ? `${url.pathname}${url.search}` : url.href;
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
	const now = options.now ?? (() => new Date());
	const randomId = options.randomId ?? (() => randomBytes(32).toString("base64url"));
	const report = options.logger === undefined ? undefined : createSanitizedReporter(options.logger);
	const router = express.Router();

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
					correlationId: requestIdOf(res),
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
			const outcome = await checkWithFailMode(
				{
					limiter: options.rateLimiter,
					tag: FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX,
					failMode: options.failMode,
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
	 * Admits a handler that writes into the shutdown drain, as the JSON routes
	 * are admitted: a drain waits for what it admitted, and a callback it did
	 * not admit could consume its transaction and then have the grant store
	 * closed under it before the credential is written (Codex). Once the drain
	 * has begun, new work is refused before it touches anything.
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
					report?.({
						during: "connect_intent",
						error,
						grantId: "",
						correlationId: requestIdOf(res),
					});
					plain(res, 503, "Temporarily unavailable.");
					return;
				}
				if (intent === null) {
					failed(req, res, "stale");
					plain(res, 400, "This link has expired or has already been used. Start again.");
					return;
				}
				// Not signed in: sign in first and come back to exactly this link —
				// its handle and nothing else from the original query.
				if (!authenticated(req)) {
					const login = options.loginUrl();
					const joiner = login.includes("?") ? "&" : "?";
					res.redirect(
						303,
						`${login}${joiner}redirect_to=${encodeURIComponent(
							federationGrantConnectUri(options.issuer, handle),
						)}`,
					);
					return;
				}
				const judged = await judge(options, req, intent, now);
				if (!judged.ok) {
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
					report?.({
						during: "connect_park",
						error,
						grantId: intent.grantId,
						correlationId: requestIdOf(res),
					});
					plain(res, 503, "Temporarily unavailable.");
					return;
				}
				if (parked === null) {
					plain(res, 400, "This link has expired or has already been used. Start again.");
					return;
				}
				res.redirect(303, consentLocation(options.consentUrl, options.issuer, parked.challenge));
			} catch (error) {
				report?.({ during: "connect", error, grantId: "", correlationId: requestIdOf(res) });
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
		if (!authenticated(req)) {
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
		try {
			consent = await options.intentStore.getConsent(presented, now());
			if (consent !== null)
				intent = await options.intentStore.getIntent(consent.intentHandle, now());
		} catch (error) {
			report?.({ during: "consent_read", error, grantId: "", correlationId: requestIdOf(res) });
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
			binding.sid !== durableSidOf(req) ||
			binding.subject !== subjectOf(req)
		) {
			jsonError(res, 400, "invalid_request", NO_PENDING);
			return null;
		}
		const judged = await judge(options, req, intent, now);
		if (!judged.ok) {
			failed(req, res, judged.reason, intent);
			if (judged.reason === "reauthentication_required") {
				jsonError(res, 403, "reauthentication_required", "sign in again to continue");
			} else if (judged.reason === "unavailable") {
				jsonError(res, 503, "temporarily_unavailable", "storage");
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

	router.get("/consent", consentThrottle, async (req, res) => {
		try {
			const found = await pendingFor(req, res, req.query.challenge);
			if (found === null) return;
			const { consent, intent } = found;
			let client: Awaited<ReturnType<ClientRepository["findById"]>>;
			try {
				client = await options.clientRepository.findById(intent.clientId);
			} catch (error) {
				report?.({
					during: "consent_client",
					error,
					grantId: intent.grantId,
					correlationId: requestIdOf(res),
				});
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
				// The grant's duration, counted from the answer — an absolute date
				// computed now would be an estimate the grant does not keep (D3).
				grant_expires_in: Math.floor(consent.lifetimeMs / 1000),
				// What D8 obliges the page to say, as data rather than as prose.
				continues_after_logout: true,
				expires_in: Math.max(0, Math.floor((consent.expiresAt.getTime() - now().getTime()) / 1000)),
			});
		} catch (error) {
			report?.({ during: "consent_get", error, grantId: "", correlationId: requestIdOf(res) });
			jsonError(res, 500, "server_error", "unexpected_error");
		}
	});

	router.post(
		"/consent",
		consentThrottle,
		express.json({ limit: BODY_LIMIT }),
		express.urlencoded({ extended: false, limit: BODY_LIMIT }),
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
				const decision = body.decision;
				if (decision !== "accept" && decision !== "deny") {
					// Refused with the question still parked: nothing was answered.
					jsonError(res, 400, "invalid_request", 'decision must be "accept" or "deny"');
					return;
				}

				if (decision === "deny") {
					const answered = await options.intentStore.answerConsent({
						challenge,
						binding,
						answer: { decision: "deny" },
						now: now(),
					});
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
							report?.({
								during: "consent_retire",
								error,
								grantId: intent.grantId,
								correlationId: requestIdOf(res),
							});
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
					jsonError(res, 503, "temporarily_unavailable", "upstream_unavailable");
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
					report?.({
						during: "consent_authorize_url",
						error,
						grantId: intent.grantId,
						correlationId: requestIdOf(res),
					});
					jsonError(res, 503, "temporarily_unavailable", "upstream_unavailable");
					return;
				}
				const answered = await options.intentStore.answerConsent({
					challenge,
					binding,
					answer: { decision: "accept", state, codeVerifier, nonce },
					now: now(),
				});
				if (answered.outcome === "refused") {
					jsonError(res, 503, "temporarily_unavailable", "storage");
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
				report?.({ during: "consent_post", error, grantId: "", correlationId: requestIdOf(res) });
				jsonError(res, 500, "server_error", "unexpected_error");
			}
		}),
	);

	// --- GET /callback/:connection -----------------------------------------
	/**
	 * Where the upstream returns the browser (D7). Query mode only: a
	 * `form_post` callback arrives without the session cookie, and check 3
	 * could not run — boot refuses such a federation.
	 *
	 * Check 1 decides whether there is anywhere trustworthy to send the browser
	 * at all, so its failures are a plain 400 from here. Every later failure
	 * goes back to the intent's own `redirect_uri` with the client's own
	 * `state`, the `grant_id`, and one of D7's ten codes — never an upstream's
	 * description, a thrown message, or anything the callback carried.
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
					report?.({ during: "callback_transaction", error, grantId: "", correlationId });
					plain(res, 503, "Temporarily unavailable.");
					return;
				}
				if (transaction === null) {
					failed(req, res, "unknown_transaction");
					plain(res, 400, "This request has expired or has already been used. Start again.");
					return;
				}
			} catch (error) {
				report?.({ during: "callback", error, grantId: "", correlationId });
				plain(res, 500, "Something went wrong.");
				return;
			}

			const { intent } = transaction;
			/** Every terminal outcome after check 1 ends here: the flow is over either way. */
			const finish = async (): Promise<void> => {
				try {
					await options.intentStore.finishIntent(intent.handle, now());
				} catch (error) {
					// Cannot undo anything, and the flow budget ends it regardless.
					report?.({ during: "callback_finish", error, grantId: intent.grantId, correlationId });
				}
			};
			const fail = async (code: CallbackError): Promise<void> => {
				failed(req, res, code, intent);
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
				try {
					grantsBoundary = await readBoundary(options.grantsBoundary, intent.subject);
					if (!(await options.grantStore.isCurrentIntent(intent.grantId, intent.handle, at))) {
						await fail("grant_not_authorizable");
						return;
					}
				} catch (error) {
					report?.({ during: "callback_current", error, grantId: intent.grantId, correlationId });
					await fail("temporarily_unavailable");
					return;
				}
				if (!pinned(connection, intent)) {
					await fail("grant_not_authorizable");
					return;
				}
				if (intent.kind === "reauthorization") {
					const backstopped = await backstop(intent, grantsBoundary, audit, correlationId);
					if (backstopped !== "clear") {
						await fail(
							backstopped === "revoked" ? "grant_not_authorizable" : "temporarily_unavailable",
						);
						return;
					}
				}

				// 3. The browser the flow started in, still live, the intent's
				// subject's, and signed in after the subject's sessions boundary.
				const session = await sessionHolds(req, transaction);
				if (session !== "ok") {
					await fail(session);
					return;
				}

				// 4. The upstream's own answer, validated by the adapter.
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
					});
				} catch (error) {
					report?.({ during: "callback_exchange", error, grantId: intent.grantId, correlationId });
					await fail(isOutage(error) ? "temporarily_unavailable" : "upstream_error");
					return;
				}
				const receivedAt = now().getTime();

				// 5. Account binding.
				const bound = await accountHolds(intent, connection, exchanged.upstream, correlationId);
				if (bound !== "ok") {
					await fail(bound);
					return;
				}

				// 6. Eligibility (D5): a refresh token, and an access token this
				// provider may disclose — judged on its lifetime and type here, and
				// on its scope in step 7, so that each failure names its own check.
				const tokens = exchanged.tokens;
				const refreshToken =
					typeof tokens.refreshToken === "string" && tokens.refreshToken.length > 0
						? tokens.refreshToken
						: undefined;
				if (refreshToken === undefined) {
					await fail("refresh_token_absent");
					return;
				}
				const scopeText = tokens.scope;
				const granted =
					scopeText === undefined
						? [...transaction.consent.scopes]
						: scopeText.split(" ").filter(Boolean);
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

				// The mandatory re-read, immediately before the write. The upstream
				// work above may have taken seconds, and a subject-wide revocation
				// may have landed in them — a "keep" stamps the sessions boundary
				// and nothing else. This narrows what was an attacker-controlled
				// window (hold the upstream redirect, finish the callback minutes
				// later) to the gap between these reads and the activation. It does
				// not close it; that needs write fencing (D13).
				const again = await sessionHolds(req, transaction);
				if (again !== "ok") {
					await fail(again);
					return;
				}
				try {
					const boundaryNow = await readBoundary(options.grantsBoundary, intent.subject);
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
					report?.({ during: "callback_reread", error, grantId: intent.grantId, correlationId });
					await fail("temporarily_unavailable");
					return;
				}

				// 8. The guarded activation (D2).
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
							...(intent.resource === undefined ? {} : { resource: intent.resource }),
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
					report?.({ during: "callback_activate", error, grantId: intent.grantId, correlationId });
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
							correlationId,
							grantId: grant.id,
							clientId: grant.clientId,
							subject: grant.subject,
							...federationGrantAuditMetadata(grant),
							outcome: options.identityLookup,
						}).catch(() => undefined),
					);
				} else {
					options.background.register(
						audit({
							type: "federation.grant.reauthorized",
							correlationId,
							grantId: grant.id,
							clientId: grant.clientId,
							subject: grant.subject,
							...federationGrantAuditMetadata(grant),
							outcome: options.identityLookup,
						}).catch(() => undefined),
					);
				}
				await finish();
				res.redirect(303, clientReturn(intent));
			} catch (error) {
				report?.({ during: "callback", error, grantId: intent.grantId, correlationId });
				await fail("temporarily_unavailable");
			}
		}),
	);

	/**
	 * Check 3, asked twice: before the exchange and again just before the
	 * activation. The browser presents the same express-session record and the
	 * same durable session the flow started in; that session is live, is the
	 * intent's subject's, and authenticated after the sessions boundary.
	 */
	async function sessionHolds(
		req: Request,
		transaction: FederationGrantConnectTransaction,
	): Promise<"ok" | "reauthentication_required" | "account_mismatch" | "temporarily_unavailable"> {
		const { binding, intent } = transaction;
		if (!authenticated(req)) return "reauthentication_required";
		if (subjectOf(req) !== intent.subject || binding.subject !== intent.subject) {
			return "account_mismatch";
		}
		if (sessionIdOf(req) !== binding.sessionId || durableSidOf(req) !== binding.sid) {
			return "reauthentication_required";
		}
		try {
			const durable = await options.userSessionStore.get(binding.sid);
			if (
				durable === null ||
				durable === undefined ||
				durable.sub !== intent.subject ||
				!(now().getTime() < durable.expiresAt.getTime())
			) {
				return "reauthentication_required";
			}
			const boundary = await readBoundary(options.sessionsBoundary, intent.subject);
			if (coveredByRevocationBoundary(durable.authTime, boundary, options.revocationSkewMs)) {
				return "reauthentication_required";
			}
		} catch {
			return "temporarily_unavailable";
		}
		return "ok";
	}

	/**
	 * A renewal's backstop (D13, amended in slice 5): the grant it would renew,
	 * compared with the subject's GRANTS boundary. A hit is revoked, durably —
	 * the one failure here meant to change the record — and audited once, by
	 * whichever call wrote it.
	 */
	async function backstop(
		intent: FederationGrantIntent,
		boundary: Date | null,
		audit: ReturnType<typeof auditFor>,
		correlationId: string,
	): Promise<"clear" | "revoked" | "unavailable"> {
		try {
			const grant = await options.grantStore.find(intent.grantId, now());
			if (grant === null || grant.status === "revoked") return "revoked";
			if (grant.status === "pending") return "clear";
			if (!coveredByRevocationBoundary(grant.consent.at, boundary, options.revocationSkewMs)) {
				return "clear";
			}
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
		} catch {
			return "unavailable";
		}
	}

	/**
	 * Check 5. The verified issuer is the connection's; a renewal's upstream
	 * account is the one already on the grant; an expectation the client
	 * lodged is met; and — unless the deployment recorded that it cannot ask —
	 * the upstream account is not already another local user's. One linked to
	 * nobody is accepted.
	 */
	async function accountHolds(
		intent: FederationGrantIntent,
		connection: FederationGrantAcquisitionConnection,
		upstream: { readonly issuer: string; readonly subject: string },
		correlationId: string,
	): Promise<
		"ok" | "account_mismatch" | "identity_conflict" | "upstream_error" | "temporarily_unavailable"
	> {
		if (upstream.issuer !== connection.upstreamIssuer) return "upstream_error";
		if (intent.upstreamSubject !== undefined && upstream.subject !== intent.upstreamSubject) {
			return "account_mismatch";
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
					return "account_mismatch";
				}
			} catch {
				return "temporarily_unavailable";
			}
		}
		if (options.identityLookup === "required") {
			// Called THROUGH the repository, never detached from it: a Store written
			// as a class reads its own fields, and `this` is lost the moment the
			// method is taken off the object — which every test stub written as an
			// arrow function hid, and the bundled repository did not (Codex).
			const repository = options.userRepository;
			if (typeof repository?.findSubjectByFederatedIdentity !== "function") {
				return "temporarily_unavailable";
			}
			try {
				const owner = await repository.findSubjectByFederatedIdentity({
					provider: intent.federation,
					sub: upstream.subject,
				});
				if (owner !== null && owner !== intent.subject) return "identity_conflict";
			} catch (error) {
				report?.({
					during: "callback_identity_lookup",
					error,
					grantId: intent.grantId,
					correlationId,
				});
				return "temporarily_unavailable";
			}
		}
		return "ok";
	}

	// Everything else under the mount: plain, not the JSON router's 404.
	router.use((_req, res) => plain(res, 404, "Not found."));
	const parserErrors: ErrorRequestHandler = (error, _req, res, next) => {
		if (res.headersSent) return next(error);
		const type = (error as { type?: unknown }).type;
		if (type === "entity.too.large")
			return jsonError(res, 413, "invalid_request", "body_too_large");
		if (type === "entity.parse.failed" || type === "encoding.unsupported") {
			return jsonError(res, 400, "invalid_request", "malformed_body");
		}
		jsonError(res, 500, "server_error", "unexpected_error");
	};
	router.use(parserErrors);
	return router;
}

/** D7's ten codes: what a failed callback sends back to the client, and nothing else. */
type CallbackError =
	| "access_denied"
	| "reauthentication_required"
	| "account_mismatch"
	| "identity_conflict"
	| "refresh_token_absent"
	| "upstream_token_ineligible"
	| "scope_exceeded"
	| "upstream_error"
	| "temporarily_unavailable"
	| "grant_not_authorizable";

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

/** Whether the connection is still what the intent was lodged against (D4). */
function pinned(
	connection: FederationGrantAcquisitionConnection | undefined,
	intent: FederationGrantIntent,
): connection is FederationGrantAcquisitionConnection {
	return (
		connection !== undefined &&
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

/** A failure to REACH the upstream — not one it answered — is an outage, not an upstream error. */
function isOutage(error: unknown): boolean {
	const name = (error as { name?: unknown })?.name;
	if (name === "AbortError" || name === "TimeoutError") return true;
	const cause = (error as { cause?: unknown })?.cause;
	const causeName = (cause as { name?: unknown })?.name;
	if (causeName === "AbortError" || causeName === "TimeoutError") return true;
	const message = `${(error as Error)?.message ?? ""} ${(cause as Error)?.message ?? ""}`;
	return /fetch failed|ECONNREFUSED|ECONNRESET|ENOTFOUND|ETIMEDOUT|EAI_AGAIN/.test(message);
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

/** What a disabled deployment mounts here: a plain 404, indistinguishable from nothing. */
export function createDisabledFederationGrantBrowserRouter(): Router {
	const router = express.Router();
	router.use(noStoreNoReferrer);
	router.use((_req, res) => plain(res, 404, "Not found."));
	return router;
}
