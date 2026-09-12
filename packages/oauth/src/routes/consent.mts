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
 * The consent step for clients that are not first-party (#527).
 *
 * `/authorize` mints a code for a first-party client as soon as the session is
 * authenticated. For any other client the user has to be asked — and the
 * page that asks is the deployment's, like the login page (`endpoints.login.url`):
 * `/authorize` parks the request under an unguessable challenge, redirects to
 * `endpoints.consent.url?challenge=…`, and this router is what the page talks
 * to:
 *
 * - `GET /oauth/consent?challenge=…` says what is being asked: the client's
 *   registered name and URI, the scopes, what the user already agreed to
 *   (so the page can highlight the delta), and where the response will go.
 * - `POST /oauth/consent` takes the answer. `accept` records the consent —
 *   the union of what was already granted and what is asked — and sends the
 *   browser back to the parked `/authorize` request, which now finds the
 *   record and mints. `deny` sends the browser to the client's `redirect_uri`
 *   with `access_denied`, as RFC 6749 §4.1.2.1 says.
 *
 * ## Why the challenge is enough against CSRF
 *
 * The challenge is 32 random bytes, bound to the session that parked the
 * request, and only ever handed to the page through the redirect URL. A
 * cross-site page cannot read that URL (same-origin policy) and cannot make
 * the browser POST a value it does not hold, so a request carrying the
 * matching challenge was composed by same-origin code — the synchronizer-
 * token pattern, with the session as the synchronizer. A stale, foreign or
 * expired challenge is `400`, never a silent no-op.
 *
 * ## Why the parked request is a record of its own (#552)
 *
 * It used to be a field on the express session. express-session hands every
 * request a snapshot and writes it back on save, so two answers in flight for
 * one challenge — a duplicated tab, a double submit — both read the field,
 * both passed, and both applied: an accept and a deny, in either order, with
 * the accept's grant standing although the user denied. The record now lives
 * in a `PendingConsentStore`, addressed by the challenge and naming the
 * session and subject it was issued to, and the answer **consumes** it in one
 * step. The page's `GET` reads without spending; the `POST` is handed the
 * record exactly once, and the second answer is told there is nothing to
 * answer. The federation callback keeps its ephemeral state the same way
 * (#494).
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import {
	type AuditSink,
	type ClientRepository,
	type ConsentStore,
	emitAuditEvent,
	type Logger,
	type PendingConsentRecord,
	type PendingConsentStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";

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
	/** #552: where `/authorize` parked the request; the answer consumes it. */
	readonly pendingConsentStore: PendingConsentStore;
	readonly clientRepository: ClientRepository;
	/**
	 * #527 review: the durable session behind the cookie. `/authorize`
	 * re-reads it before it mints anything, and these endpoints must too —
	 * a session revoked out of band while the browser still holds its cookie
	 * and its parked challenge would otherwise record a consent that a later
	 * login then inherits without ever being asked.
	 */
	readonly userSessionStore?: UserSessionStore;
	readonly auditSink?: AuditSink;
	readonly logger: Logger;
}

const jsonError = (res: Response, status: number, error: string, description: string): Response =>
	res
		.status(status)
		.set("Cache-Control", "no-store")
		.json({ error, error_description: description });

/**
 * One answer for every way a challenge can have nothing behind it — answered
 * already, expired, never issued, or issued to another session — so the
 * response does not say which, and still tells the page what to do. The
 * store hides an expired record the same way it hides an unknown one, which
 * is why expiry is named here rather than detected separately.
 */
const NO_PENDING =
	"no pending consent for this challenge — it was answered, has expired, or was not issued to this session; start again";

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

const subjectOf = (req: Request): string | null => {
	const id = req.session?.user?.id;
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
	} = opts;

	/**
	 * The parked request the presented challenge names, read without spending
	 * it, or `null` after an error has been sent. One reader for both
	 * methods, so the page cannot learn something on GET that the POST would
	 * then refuse. A record issued to another session is "no pending consent"
	 * — the challenge is not a bearer token, and the answer does not say
	 * whether one exists elsewhere.
	 */
	const pendingFor = async (
		req: Request,
		res: Response,
		challenge: unknown,
	): Promise<PendingConsentRecord | null> => {
		if (!req.session?.isAuthenticated) {
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
			logger.error({ err }, "pending_consent_store_unavailable");
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
	 * Whether the cookie's session is still the live one. The same read
	 * `/authorize` does before it mints a code: a `sid` the store no longer
	 * knows is a session someone revoked, and an answer given through it is
	 * not the user's. A store that cannot answer fails closed, because the
	 * alternative is recording a consent on an unknown session.
	 */
	const sessionIsLive = async (req: Request): Promise<boolean> => {
		const sid = typeof req.session?.sid === "string" ? req.session.sid : undefined;
		if (!userSessionStore || sid === undefined) return true;
		try {
			return (await userSessionStore.get(sid)) != null;
		} catch (err) {
			logger.warn({ err, sid }, "consent_session_liveness_unavailable");
			return false;
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
			logger.error({ err }, "pending_consent_store_unavailable");
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
			logger.error({ err, clientId: pending.clientId }, "consent_client_repository_unavailable");
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
	router.use(express.json());
	router.use(express.urlencoded({ extended: false }));

	router.get("/consent", async (req, res) => {
		const pending = await pendingFor(req, res, req.query.challenge);
		if (pending === null) return;
		if (!(await sessionIsLive(req))) {
			return jsonError(res, 401, "login_required", "the session is no longer active");
		}
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
		if (!(await sessionIsLive(req))) {
			return jsonError(res, 401, "login_required", "the session is no longer active");
		}
		const sub = subjectOf(req);
		if (sub === null) {
			return jsonError(
				res,
				400,
				"invalid_request",
				"the session names no subject to record consent for",
			);
		}
		if (sub !== peeked.sub) {
			// The record was asked of someone else: not this session's to answer.
			return jsonError(res, 400, "invalid_request", NO_PENDING);
		}
		const decision = body.decision;
		if (decision !== "accept" && decision !== "deny") {
			return jsonError(res, 400, "invalid_request", 'decision must be "accept" or "deny"');
		}
		// The client has to exist when the answer is given, not only when the
		// page was shown: a registration removed in between is a consent for
		// nobody, and a grant recorded under its id would greet whoever is
		// registered under that id next (#552 review).
		if ((await clientFor(res, peeked)) === null) return;

		// One answer per challenge, whichever way it went: the record is handed
		// to exactly one of any number of answers in flight, and the others
		// find nothing (#552).
		let pending: PendingConsentRecord | null;
		try {
			pending = await pendingConsentStore.consume(peeked.challenge);
		} catch (err) {
			logger.error({ err, clientId: peeked.clientId }, "pending_consent_store_unavailable");
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
			const url = new URL(pending.redirectUri);
			url.searchParams.append("error", "access_denied");
			url.searchParams.append("error_description", "the resource owner denied the request");
			if (pending.state !== undefined) url.searchParams.append("state", pending.state);
			return res.redirect(303, url.toString());
		}

		// The union, not the request: consenting to `write` today must not
		// silently withdraw the `read` consented to last month.
		const scopes = [...new Set([...pending.grantedScopes, ...pending.scopes])];
		try {
			await consentStore.grant({ sub, clientId: pending.clientId, scopes, grantedAt: Date.now() });
		} catch (err) {
			logger.error({ err, clientId: pending.clientId }, "consent_store_unavailable");
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
