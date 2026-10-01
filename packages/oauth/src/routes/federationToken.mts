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
 * session, client, linked federation), whose session read core's
 * session-admission drift guard pins to this file.
 */

import {
	auditErrorText,
	emitAuditEvent,
	logClientRepositoryUnavailable,
	loggableError,
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
import { refreshStoredTokens } from "./federationTokenRefresh.mjs";
import { answerStoredToken, readStoredTokens } from "./federationTokenStored.mjs";

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
	const { opts, req, res, name, federation, logger, storeUnavailable } = ctx;
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

	// Step 6: Load session. null → 401 invalid_token. Throw → 503.
	let session: Awaited<ReturnType<typeof opts.userSessionStore.get>>;
	try {
		session = await opts.userSessionStore.get(sid);
	} catch (error) {
		storeUnavailable(federation, "user_session", "get", error);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		return false;
	}
	if (!session) {
		res.setHeader(
			"WWW-Authenticate",
			'Bearer error="invalid_token", error_description="session not found"',
		);
		res.status(401).json({
			error: "invalid_token",
			error_description: "session not found",
		});
		return false;
	}

	// The federation index, read for step 8's membership check.
	let federations: ReadonlyArray<string>;
	try {
		federations = await opts.sessionFederationIndex.listFederations(sid);
	} catch (error) {
		storeUnavailable(federation, "session_federation_index", "list", error);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		return false;
	}

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

/**
 * POST /federation/:name/token — the federation token proxy. Returns the
 * user's upstream federation access token to an opted-in client: the caller
 * presents a valid at+jwt access token, and the client named by its `azp`
 * must have `allowedAzpForFederationToken: true`.
 *
 * Mounted under /oauth → POST /oauth/federation/:name/token.
 */
export function createRouter(express: ExpressLike, opts: FederationTokenRouterOptions): Router {
	// Refused, never repaired: 0 or less serves a token with no life left, and
	// NaN never serves the stored token, so every request refreshes upstream.
	const refreshBufferMs = opts.refreshBufferMs ?? 30_000;
	if (
		typeof refreshBufferMs !== "number" ||
		!Number.isFinite(refreshBufferMs) ||
		refreshBufferMs <= 0
	) {
		throw new RangeError(
			"federation token route: refreshBufferMs must be a positive finite number",
		);
	}
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
		};
		const caller = await identifyCaller(ctx);
		if (caller === null) return;
		if (!(await checkCallerStanding(ctx, caller))) return;

		const tokens = await readStoredTokens(ctx, caller);
		if (tokens === null) return;

		// Step 10: not expiring within the buffer → return the stored token.
		// `expiresAt === null` is an upstream issuing no finite expiry (e.g.
		// GitHub OAuth App tokens): never refresh, and omit `expires_in`.
		if (tokens.expiresAt === null || tokens.expiresAt.getTime() > Date.now() + refreshBufferMs) {
			return answerStoredToken(ctx, caller, tokens);
		}

		return refreshStoredTokens(ctx, caller, tokens);
	});

	return router;
}
