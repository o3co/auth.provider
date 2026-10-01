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
 * The consent step for clients that are not first-party. `/authorize` parks
 * the request under an unguessable challenge and redirects to the
 * deployment's page (`oauth.consentPage.url?challenge=…`), which talks to
 * this router:
 *
 * - `GET /oauth/consent?challenge=…` describes the ask: client name and URI,
 *   scopes, what the user already granted, and where the response goes.
 * - `POST /oauth/consent` takes the answer. `accept` records the union of
 *   granted and asked scopes and returns the browser to the parked
 *   `/authorize` request; `deny` redirects to the client's `redirect_uri`
 *   with `access_denied` (RFC 6749 §4.1.2.1).
 *
 * CSRF: the challenge is 32 random bytes, bound to the parking session and
 * handed to the page only in the redirect URL, which a cross-site page cannot
 * read — the synchronizer-token pattern. A stale, foreign or expired
 * challenge is `400`, never a silent no-op.
 *
 * The parked request is a `PendingConsentStore` record, not a session field:
 * express-session works on per-request snapshots, so two answers in flight
 * (a double submit) would both apply. The POST consumes the record
 * atomically, so exactly one answer wins.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import {
	type AdmissionDeps,
	type AuditSink,
	admitSession,
	type ClientRepository,
	type ConsentStore,
	checkResolver,
	cookieClaim,
	describeAdmissionOutage,
	emitAuditEvent,
	type Logger,
	logClientRepositoryUnavailable,
	loggableError,
	type PendingConsentRecord,
	type PendingConsentStore,
	type SessionRequirementResolver,
	type SubjectRevocation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import type { OAUTH_ROUTER_ADMISSION_ACTIONS } from "../admissionActions.mjs";
import { isClientIdMetadataDocumentClient } from "../clients/clientIdMetadataDocument.mjs";
import type { AuthorizationResponse } from "./authorizationResponse.mjs";

/** The action the consent step admits, as `oauthModule` registers it. */
const CONSENT_ACTION = "oauth.consent" satisfies keyof typeof OAUTH_ROUTER_ADMISSION_ACTIONS;

/**
 * The host a Client ID Metadata Document client's `client_id` names, for the
 * page to show prominently: its `client_name` and `client_uri` are the
 * document author's claims, while the host is the one fact this server
 * verified. Only for document clients, not pre-registered URL-shaped ids.
 */
const clientIdHost = (clientId: string): { client_id_host: string } => ({
	// The resolver accepted this id only as a canonical `https` URL.
	client_id_host: new URL(clientId).host,
});

/** How long a parked `/authorize` request waits for the consent page. */
export const PENDING_CONSENT_TTL_MS = 10 * 60 * 1000;

export const newConsentChallenge = (): string => randomBytes(32).toString("base64url");

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export interface ConsentRouterOptions {
	readonly consentStore: ConsentStore;
	/** Where `/authorize` parked the request; the answer consumes it. */
	readonly pendingConsentStore: PendingConsentStore;
	readonly clientRepository: ClientRepository;
	/**
	 * The durable session behind the cookie, read through admission as
	 * `/authorize` does: otherwise a session revoked out of band, whose browser
	 * still holds the cookie and a parked challenge, could record a consent a
	 * later login inherits without being asked.
	 */
	readonly userSessionStore?: UserSessionStore;
	/** The subject-revocation boundary, applied to the live record when wired. */
	readonly subjectRevocation?: SubjectRevocation;
	/** The registered session requirements; required. */
	readonly requirements: SessionRequirementResolver;
	readonly auditSink?: AuditSink;
	readonly logger: Logger;
	/** Builds the deny's response to `redirect_uri`, its `iss` (RFC 9207) bound. */
	readonly authorizationResponse: AuthorizationResponse;
}

const jsonError = (res: Response, status: number, error: string, description: string): Response =>
	res
		.status(status)
		.set("Cache-Control", "no-store")
		.json({ error, error_description: description });

/**
 * One answer for every way a challenge can have nothing behind it (answered,
 * expired, never issued, another session's), so the response does not say
 * which.
 */
const NO_PENDING =
	"no pending consent for this challenge: it was answered, has expired, or was not issued to this session; start again";

const sameToken = (a: string, b: string): boolean => {
	const x = Buffer.from(a);
	const y = Buffer.from(b);
	return x.length === y.length && timingSafeEqual(x, y);
};

/** What express-session reports as this session's id, if anything. */
const sessionIdOf = (req: Request): string | null => {
	const id = (req as { sessionID?: unknown }).sessionID;
	return typeof id === "string" && id.length > 0 ? id : null;
};

export function createConsentRouter(express: ExpressLike, opts: ConsentRouterOptions): Router {
	const {
		consentStore,
		pendingConsentStore,
		clientRepository,
		auditSink,
		logger,
		userSessionStore,
		subjectRevocation,
	} = opts;
	// What admission reads for these endpoints: the router's slots as wired,
	// and no acr table, since consent asks for no acr.
	const admissionDeps: AdmissionDeps = {
		userSessionStore,
		subjectRevocation,
		requirements: checkResolver(opts.requirements, "createConsentRouter", [CONSENT_ACTION]),
		acrTable: {},
		logger,
		auditSink,
	};

	/**
	 * The parked request the challenge names, read without spending it, or
	 * `null` after an error has been sent. One reader for both methods, so GET
	 * shows nothing POST would refuse. Another session's record is "no pending
	 * consent": the challenge is not a bearer token. Only the cookie's flag is
	 * checked here; liveness and subject are `admittedSubject`'s.
	 */
	const pendingFor = async (
		req: Request,
		res: Response,
		challenge: unknown,
	): Promise<PendingConsentRecord | null> => {
		// The cookie's flag: exactly `true`, never merely truthy.
		if (!cookieClaim(req).authenticated) {
			jsonError(res, 401, "login_required", "no authenticated session");
			return null;
		}
		if (typeof challenge !== "string" || challenge.length === 0) {
			jsonError(res, 400, "invalid_request", "challenge is required");
			return null;
		}
		let pending: PendingConsentRecord | null;
		try {
			pending = await pendingConsentStore.get(challenge);
		} catch (err) {
			logger.error({ err: loggableError(err) }, "pending_consent_store_unavailable");
			jsonError(res, 503, "temporarily_unavailable", "consent store unavailable");
			return null;
		}
		const sessionId = sessionIdOf(req);
		if (pending === null || sessionId === null || !sameToken(pending.sessionId, sessionId)) {
			jsonError(res, 400, "invalid_request", NO_PENDING);
			return null;
		}
		return pending;
	};

	/**
	 * The admitted subject of the cookie's session, if it is the one the
	 * request was parked for, or `null` after the refusal has been sent. The
	 * same reading `/authorize` makes: a gone, expired, foreign or revoked
	 * session is `401 login_required`, and so is any requirement short of met
	 * (step-up included: `/authorize` decides again on return). An outage is
	 * `503` and the request stays parked. Checked on GET too, so a session
	 * reused across logout and login never shows one user another's request.
	 */
	const admittedSubject = async (
		req: Request,
		res: Response,
		pending: PendingConsentRecord,
	): Promise<string | null> => {
		const claim = cookieClaim(req);
		const admission = await admitSession(admissionDeps, {
			claim,
			action: CONSENT_ACTION,
		});
		switch (admission.outcome) {
			case "unavailable":
				jsonError(res, 503, "temporarily_unavailable", describeAdmissionOutage(admission.store));
				return null;
			case "admitted": {
				// The record's subject when one was read — admission made it the
				// claim's — else the cookie's, which an admitted cookie claim always
				// names: admission refuses one without it (`not_live`, `no_subject`).
				const sub = admission.session === null ? claim.subject : admission.session.sub;
				if (sub !== pending.sub) {
					jsonError(res, 400, "invalid_request", NO_PENDING);
					return null;
				}
				return sub;
			}
			case "not_live":
			case "revoked":
			// Never reached: `pendingFor` refused a cookie whose flag is not
			// exactly `true` before anything was read. Listed so the switch
			// stays exhaustive over core's `Admission`.
			case "unauthenticated":
				jsonError(res, 401, "login_required", "the session is no longer active");
				return null;
			case "reauthenticate":
			case "step_up":
			case "unmet":
				jsonError(
					res,
					401,
					"login_required",
					`the session does not meet the ${admission.requirement} requirement; authorize again`,
				);
				return null;
		}
	};

	/**
	 * Drop a parked request that can no longer be answered. `false` when the
	 * store refused: the record is then still there for an answer to spend,
	 * so the caller fails closed rather than reporting the request gone.
	 */
	const discard = async (challenge: string): Promise<boolean> => {
		try {
			await pendingConsentStore.consume(challenge);
			return true;
		} catch (err) {
			logger.error({ err: loggableError(err) }, "pending_consent_store_unavailable");
			return false;
		}
	};

	/**
	 * The client the parked request names, looked up now. `null` after a
	 * response has been sent: a registry outage is `503`, and a client removed
	 * since the request was parked drops the request and answers `400` — or
	 * `503` if it cannot be dropped, because a record left behind is one an
	 * answer could still spend for a client that no longer exists.
	 */
	const clientFor = async (
		res: Response,
		pending: PendingConsentRecord,
	): Promise<Awaited<ReturnType<ClientRepository["findById"]>>> => {
		let client: Awaited<ReturnType<ClientRepository["findById"]>>;
		try {
			client = await clientRepository.findById(pending.clientId);
		} catch (err) {
			// The line every client lookup writes, through core's helper.
			logClientRepositoryUnavailable(
				logger,
				{ site: "consent", step: "find", clientId: pending.clientId },
				err,
			);
			jsonError(res, 503, "temporarily_unavailable", "client registry unavailable");
			return null;
		}
		if (client === null) {
			if (!(await discard(pending.challenge))) {
				jsonError(res, 503, "temporarily_unavailable", "consent store unavailable");
				return null;
			}
			jsonError(res, 400, "invalid_request", "the client is no longer registered");
		}
		return client;
	};

	const router = express.Router();
	// Scoped to exactly the one path this router serves: it is mounted
	// without a path inside the OAuth router, so unscoped parsers would read
	// the body of every request under `/oauth` that reached it — other
	// modules' too. A route (`router.all`) rather than `router.use`, which
	// would match every path beneath `/consent` as well.
	router.all("/consent", express.json(), express.urlencoded({ extended: false }));

	router.get("/consent", async (req, res) => {
		const pending = await pendingFor(req, res, req.query.challenge);
		if (pending === null) return;
		if ((await admittedSubject(req, res, pending)) === null) return;
		// Registered when the request was parked, gone now: nothing to ask
		// about, and the parked request is dropped with it.
		const client = await clientFor(res, pending);
		if (client === null) return;
		return res
			.status(200)
			.set("Cache-Control", "no-store")
			.json({
				challenge: pending.challenge,
				client_id: pending.clientId,
				...(isClientIdMetadataDocumentClient(client) ? clientIdHost(pending.clientId) : {}),
				...(client.clientName !== undefined ? { client_name: client.clientName } : {}),
				...(client.clientUri !== undefined ? { client_uri: client.clientUri } : {}),
				scopes: pending.scopes,
				granted_scopes: pending.grantedScopes,
				redirect_uri: pending.redirectUri,
				expires_in: Math.max(0, Math.floor((pending.expiresAt - Date.now()) / 1000)),
			});
	});

	router.post("/consent", async (req, res) => {
		const body = (req.body ?? {}) as Record<string, unknown>;
		// Read first, so a malformed answer is refused with the request still
		// parked; the record is spent only once the answer is one that can be
		// applied.
		const peeked = await pendingFor(req, res, body.challenge);
		if (peeked === null) return;
		const sub = await admittedSubject(req, res, peeked);
		if (sub === null) return;
		const decision = body.decision;
		if (decision !== "accept" && decision !== "deny") {
			return jsonError(res, 400, "invalid_request", "decision must be 'accept' or 'deny'");
		}
		// The client must still exist when the answer is given: a grant recorded
		// under a removed id would greet whoever is registered under it next.
		if ((await clientFor(res, peeked)) === null) return;

		// One answer per challenge: the record is handed to exactly one of any
		// number of answers in flight, and the others find nothing.
		let pending: PendingConsentRecord | null;
		try {
			pending = await pendingConsentStore.consume(peeked.challenge);
		} catch (err) {
			logger.error(
				{ err: loggableError(err), clientId: peeked.clientId },
				"pending_consent_store_unavailable",
			);
			return jsonError(res, 503, "temporarily_unavailable", "consent store unavailable");
		}
		if (pending === null) {
			return jsonError(res, 400, "invalid_request", NO_PENDING);
		}

		if (decision === "deny") {
			await emitAuditEvent(auditSink, {
				timestamp: new Date(),
				type: "consent.denied",
				subject: sub,
				clientId: pending.clientId,
				ip: req.ip,
				userAgent: req.get("user-agent"),
				details: { scopes: pending.scopes },
			});
			const location = opts.authorizationResponse(
				pending.redirectUri,
				{ error: "access_denied", error_description: "the resource owner denied the request" },
				pending.state,
			);
			return res.redirect(303, location);
		}

		// The union, not the request: consenting to `write` today must not
		// silently withdraw the `read` consented to last month.
		const scopes = [...new Set([...pending.grantedScopes, ...pending.scopes])];
		try {
			await consentStore.grant({
				sub,
				clientId: pending.clientId,
				scopes,
				grantedAt: Date.now(),
				// Until revoked: this route asks nothing about how long.
				expiresAt: undefined,
			});
		} catch (err) {
			logger.error(
				{ err: loggableError(err), clientId: pending.clientId },
				"consent_store_unavailable",
			);
			return jsonError(res, 503, "temporarily_unavailable", "consent store unavailable");
		}
		await emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "consent.granted",
			subject: sub,
			clientId: pending.clientId,
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: { scopes },
		});
		// 303: the page POSTed; the browser must GET the parked request.
		return res.redirect(303, pending.authorizeUrl);
	});

	return router;
}
