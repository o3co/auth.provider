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
	type FederationGrantIntent,
	type FederationGrantIntentStore,
	type FederationGrantStore,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
	type Logger,
	type RateLimiter,
	type RateLimitFailMode,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
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

/** What the connect flow needs of a federation: the delegated authorization URL (D17). */
export interface FederationGrantDelegatedAuthorizer {
	buildDelegatedAuthorizationUrl(params: {
		readonly redirectUri: string;
		readonly state: string;
		readonly codeVerifier: string;
		readonly nonce: string;
		readonly scopes: readonly string[];
		readonly resource?: string;
		readonly authorizationParams?: Readonly<Record<string, string>>;
	}): URL;
}

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

	router.use(noStoreNoReferrer);
	router.use(createRequestIdMiddleware());

	// --- GET /connect ---------------------------------------------------------
	router.get(
		"/connect",
		throttle((res, status) =>
			plain(res, status, status === 429 ? "Too many requests." : "Temporarily unavailable."),
		),
		async (req, res) => {
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
		},
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
		async (req, res) => {
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
		},
	);

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
