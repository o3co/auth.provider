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
 * `/authorize` parks the request in the session under an unguessable
 * challenge, redirects to `endpoints.consent.url?challenge=…`, and this router
 * is what the page talks to:
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
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import {
	type AuditSink,
	type ClientRepository,
	type ConsentStore,
	emitAuditEvent,
	type Logger,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";

/** How long a parked `/authorize` request waits for the consent page. */
export const PENDING_CONSENT_TTL_MS = 10 * 60 * 1000;

/** What `/authorize` parks in the session while the user is asked (#527). */
export interface PendingConsent {
	readonly challenge: string;
	readonly clientId: string;
	/** The scopes the request asks for, after the client's allowlist. */
	readonly scopes: readonly string[];
	/** What the user already agreed to for this client, for the page's delta. */
	readonly grantedScopes: readonly string[];
	/** The canonical `/authorize` URL to return to once consent is recorded. */
	readonly authorizeUrl: string;
	/** The validated `redirect_uri`, where a denial goes. */
	readonly redirectUri: string;
	readonly state?: string;
	/** Epoch milliseconds. */
	readonly createdAt: number;
}

declare module "express-session" {
	interface SessionData {
		pendingConsent?: PendingConsent;
	}
}

export const newConsentChallenge = (): string => randomBytes(32).toString("base64url");

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export interface ConsentRouterOptions {
	readonly consentStore: ConsentStore;
	readonly clientRepository: ClientRepository;
	readonly auditSink?: AuditSink;
	readonly logger: Logger;
}

const jsonError = (res: Response, status: number, error: string, description: string): Response =>
	res
		.status(status)
		.set("Cache-Control", "no-store")
		.json({ error, error_description: description });

const sameChallenge = (a: string, b: string): boolean => {
	const x = Buffer.from(a);
	const y = Buffer.from(b);
	return x.length === y.length && timingSafeEqual(x, y);
};

/**
 * The parked request the presented challenge names, or `null` after a `400`
 * has been sent. One reader for both methods, so the page cannot learn
 * something on GET that the POST would then refuse.
 */
const pendingFor = (req: Request, res: Response, challenge: unknown): PendingConsent | null => {
	if (!req.session?.isAuthenticated) {
		jsonError(res, 401, "login_required", "no authenticated session");
		return null;
	}
	if (typeof challenge !== "string" || challenge.length === 0) {
		jsonError(res, 400, "invalid_request", "challenge is required");
		return null;
	}
	const pending = req.session.pendingConsent;
	if (pending === undefined || !sameChallenge(pending.challenge, challenge)) {
		jsonError(res, 400, "invalid_request", "no pending consent for this challenge");
		return null;
	}
	if (pending.createdAt + PENDING_CONSENT_TTL_MS <= Date.now()) {
		delete req.session.pendingConsent;
		jsonError(res, 400, "invalid_request", "the consent request has expired; start again");
		return null;
	}
	return pending;
};

const subjectOf = (req: Request): string | null => {
	const id = req.session?.user?.id;
	return typeof id === "string" && id.length > 0 ? id : null;
};

export function createConsentRouter(express: ExpressLike, opts: ConsentRouterOptions): Router {
	const { consentStore, clientRepository, auditSink, logger } = opts;
	const router = express.Router();
	router.use(express.json());
	router.use(express.urlencoded({ extended: false }));

	router.get("/consent", async (req, res) => {
		const pending = pendingFor(req, res, req.query.challenge);
		if (pending === null) return;
		let client: Awaited<ReturnType<ClientRepository["findById"]>>;
		try {
			client = await clientRepository.findById(pending.clientId);
		} catch (err) {
			logger.error({ err, clientId: pending.clientId }, "consent_client_repository_unavailable");
			return jsonError(res, 503, "temporarily_unavailable", "client registry unavailable");
		}
		if (client === null) {
			// Registered when the request was parked, gone now: nothing to ask
			// about. The parked request is dropped with it.
			delete req.session.pendingConsent;
			return jsonError(res, 400, "invalid_request", "the client is no longer registered");
		}
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
				expires_in: Math.max(
					0,
					Math.floor((pending.createdAt + PENDING_CONSENT_TTL_MS - Date.now()) / 1000),
				),
			});
	});

	router.post("/consent", async (req, res) => {
		const body = (req.body ?? {}) as Record<string, unknown>;
		const pending = pendingFor(req, res, body.challenge);
		if (pending === null) return;
		const sub = subjectOf(req);
		if (sub === null) {
			return jsonError(
				res,
				400,
				"invalid_request",
				"the session names no subject to record consent for",
			);
		}
		const decision = body.decision;
		if (decision !== "accept" && decision !== "deny") {
			return jsonError(res, 400, "invalid_request", 'decision must be "accept" or "deny"');
		}
		// One answer per challenge, whichever way it went.
		delete req.session.pendingConsent;

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
