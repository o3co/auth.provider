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
 * The federation token route: the handler, which runs the stages in order and
 * stops at the first that answers, and the caller's standing (refresh family,
 * session, client, linked federation). Whether the session is live and which
 * federations it joined are read from core's session lifecycle.
 */

import {
	auditErrorText,
	emitAuditEvent,
	logClientRepositoryUnavailable,
	loggableError,
	type SessionFederations,
	sanitizeErrorText,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";
import { identifyCaller } from "./federationTokenCaller.mjs";
import {
	createStoreUnavailableLog,
	type FederationTokenCaller,
	type FederationTokenContext,
	type FederationTokenRouterOptions,
} from "./federationTokenContext.mjs";
import { readRecord, serveStored } from "./federationTokenRecord.mjs";
import { refreshStoredTokens } from "./federationTokenRefresh.mjs";
import { REFRESH_FLOOR_MS } from "./federationTokenRefreshAnswer.mjs";
import { createRefreshBackoff } from "./federationTokenRefreshBackoff.mjs";
import { refreshIsDue } from "./federationTokenRefreshDue.mjs";
import { checkSessionLive } from "./federationTokenSession.mjs";

export type { FederationTokenRouterOptions } from "./federationTokenContext.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

/**
 * Steps 5 to 8, the caller's standing: its refresh family is not revoked, its
 * session is live, its client may use this route, and the federation is
 * linked to the session. Returns `false` once answered.
 */
const checkCallerStanding = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
): Promise<boolean> => {
	const { opts, req, res, name, federation, logger } = ctx;
	const { familyId, sid, azp, sub } = caller;

	// Step 5: family revocation, fail-closed. A throw is `503`, never `401
	// invalid_token`, which would send the client to replace a token nobody
	// could judge (RFC 6750 §3.1).
	let revoked: boolean;
	try {
		revoked = await opts.refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
	} catch (error) {
		logger.error(
			{ federation, store: "refresh_token_family", err: loggableError(error) },
			"federation_token_store_unavailable",
		);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "refresh token store unavailable",
		});
		return false;
	}
	if (revoked) {
		emitAuditEvent(opts.auditSink, {
			timestamp: new Date(),
			type: "federation.token.family_revoked",
			subject: sub ?? undefined,
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: { sid },
		});
		res.setHeader(
			"WWW-Authenticate",
			'Bearer error="invalid_token", error_description="family revoked"',
		);
		res.status(401).json({
			error: "invalid_token",
			error_description: "family revoked",
		});
		return false;
	}

	// Step 6: the session must be live.
	if (!(await checkSessionLive(ctx, caller))) return false;

	// The federations the session joined, read for step 8's membership check.
	// One a federation logout disconnected stays listed with its tokens
	// removed; step 9 answers it as a federation with no tokens.
	let listed: SessionFederations;
	try {
		listed = await opts.sessionLifecycle.federations(sid);
	} catch (error) {
		logger.error(
			{ federation, store: "session_lifecycle", step: "federations", err: loggableError(error) },
			"federation_token_store_unavailable",
		);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		return false;
	}
	// Any answer other than `listed` (core's lifecycle gives none, as it
	// rejects on an outage) is answered as the outage.
	if (listed.outcome !== "listed") {
		logger.error(
			{ federation, store: "session_lifecycle", step: "federations" },
			"federation_token_store_unavailable",
		);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		return false;
	}
	const federations = listed.federations;

	// Step 7: Client must exist AND have allowedAzpForFederationToken === true.
	let client: Awaited<ReturnType<typeof opts.clientRepository.findById>>;
	try {
		client = await opts.clientRepository.findById(azp);
	} catch (error) {
		logClientRepositoryUnavailable(
			logger,
			{ site: "federation_token", step: "find", clientId: azp },
			error,
		);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "client repository unavailable",
		});
		return false;
	}
	if (!client?.allowedAzpForFederationToken) {
		emitAuditEvent(opts.auditSink, {
			timestamp: new Date(),
			type: "federation.token.forbidden",
			subject: sub ?? undefined,
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: { federation, azp },
		});
		res.status(403).json({
			error: "forbidden",
			error_description: "client is not permitted to access federation tokens",
		});
		return false;
	}

	// Step 8: Federation must be linked to this session.
	if (!federations.includes(name)) {
		res.status(404).json({
			error: "federation_not_linked",
			error_description: sanitizeErrorText(`federation '${name}' is not linked to this session`),
		});
		return false;
	}
	return true;
};

const MIN_REFRESH_BUFFER_MS = REFRESH_FLOOR_MS;
const MAX_REFRESH_BUFFER_MS = 2 ** 31 - 1;
const DEFAULT_MAX_TOKEN_LIFETIME_MS = 86_400_000;
const MAX_MAX_TOKEN_LIFETIME_DAYS = 365;
const MAX_MAX_TOKEN_LIFETIME_MS = MAX_MAX_TOKEN_LIFETIME_DAYS * 86_400_000;

/**
 * POST /federation/:name/token — the federation token proxy. Returns the
 * user's upstream federation access token to an opted-in client: the caller
 * presents a valid at+jwt access token issued for the client named by its
 * `azp` (its `aud` contains that id), and that client must have
 * `allowedAzpForFederationToken: true`.
 *
 * Mounted under /oauth → POST /oauth/federation/:name/token.
 */
export function createRouter(express: ExpressLike, opts: FederationTokenRouterOptions): Router {
	// Refused, never repaired: 0 or less serves a token with no life left,
	// NaN never serves the stored token, and under a second sits below the
	// refresh reading's own one-second floor. Only an absent option takes the
	// default; `null` is refused like any other non-number.
	const refreshBufferMs: unknown =
		opts.refreshBufferMs === undefined ? 30_000 : opts.refreshBufferMs;
	if (
		typeof refreshBufferMs !== "number" ||
		!Number.isInteger(refreshBufferMs) ||
		refreshBufferMs < MIN_REFRESH_BUFFER_MS ||
		refreshBufferMs > MAX_REFRESH_BUFFER_MS
	) {
		throw new RangeError(
			`federation token route: refreshBufferMs must be a whole number of milliseconds from ${MIN_REFRESH_BUFFER_MS} to ${MAX_REFRESH_BUFFER_MS}`,
		);
	}
	// At or below the buffer, every refreshed token would be stored already
	// due, and every request would refresh upstream.
	const maxTokenLifetimeMs: unknown =
		opts.maxTokenLifetimeMs === undefined ? DEFAULT_MAX_TOKEN_LIFETIME_MS : opts.maxTokenLifetimeMs;
	if (
		typeof maxTokenLifetimeMs !== "number" ||
		!Number.isInteger(maxTokenLifetimeMs) ||
		maxTokenLifetimeMs <= refreshBufferMs ||
		maxTokenLifetimeMs > MAX_MAX_TOKEN_LIFETIME_MS
	) {
		throw new RangeError(
			`federation token route: maxTokenLifetimeMs must be a whole number of milliseconds greater than refreshBufferMs (${refreshBufferMs}) and at most ${MAX_MAX_TOKEN_LIFETIME_DAYS} days (${MAX_MAX_TOKEN_LIFETIME_MS}), got ${opts.maxTokenLifetimeMs === undefined ? `the default ${DEFAULT_MAX_TOKEN_LIFETIME_MS}` : String(opts.maxTokenLifetimeMs)}; with a refreshBufferMs of 24 h or more, pass a larger maxTokenLifetimeMs`,
		);
	}
	const refreshBackoff = createRefreshBackoff();
	const router = express.Router();

	router.post("/federation/:name/token", async (req: Request, res: Response) => {
		const { name } = req.params as { name: string };
		// The path parameter is the caller's text, logged before any membership
		// check: every log line and every audit event carries it sanitised and
		// capped, as a client id is — `federation.token.forbidden` fires before
		// the linked-federation check.
		const federation = auditErrorText(name);
		const logger = opts.logger ?? console;
		const storeUnavailable = createStoreUnavailableLog(logger);

		// RFC 6749 §5.1 / RFC 9207: cache headers on every response path.
		res.setHeader("Cache-Control", "no-store");
		res.setHeader("Pragma", "no-cache");

		const ctx: FederationTokenContext = {
			opts,
			req,
			res,
			name,
			federation,
			logger,
			storeUnavailable,
			refreshBufferMs,
			maxTokenLifetimeMs,
			refreshBackoff,
		};
		const caller = await identifyCaller(ctx);
		if (caller === null) return;
		if (!(await checkCallerStanding(ctx, caller))) return;

		// Step 9: the stored record. None is `404`; an outage `503`.
		const read = await readRecord(ctx, caller, "get");
		if (read === null) return;

		// Step 10: a token not yet due is returned as stored; one with no
		// finite expiry omits `expires_in`.
		if (!refreshIsDue(ctx, read.value)) {
			return serveStored(ctx, caller, read);
		}

		return refreshStoredTokens(ctx, caller, read);
	});

	return router;
}
