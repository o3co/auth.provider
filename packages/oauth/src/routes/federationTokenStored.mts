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
 * The user's stored upstream tokens: read before any refresh, a link with no
 * record removed from the session's index (best effort) and answered `404`,
 * and handed on as stored while they do not expire within the refresh buffer.
 */

import {
	BEARER_TOKEN_TYPE,
	emitAuditEvent,
	type FederationTokens,
	loggableError,
	sanitizeErrorText,
} from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import {
	mayDiscloseTokenType,
	refuseUndisclosableTokenType,
} from "./federationTokenDisclosure.mjs";

/**
 * Step 9: the record for this session and federation. Returns it, or `null`
 * once answered.
 */
export const readStoredTokens = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
): Promise<FederationTokens | null> => {
	const { opts, res, name, federation, logger, storeUnavailable } = ctx;
	const { sid } = caller;

	// Step 9: Get federation tokens. Throw → 503. null → self-heal + 404.
	let tokens: Awaited<ReturnType<typeof opts.federationTokenStore.get>>;
	try {
		tokens = await opts.federationTokenStore.get(sid, name);
	} catch (error) {
		storeUnavailable(federation, "federation_token", "get", error);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "federation token store unavailable",
		});
		return null;
	}
	if (!tokens) {
		// Self-heal: federation link is dangling — remove from federation index.
		try {
			await opts.sessionFederationIndex.removeFederation(sid, name);
		} catch (error) {
			logger.warn(
				{
					federation,
					store: "session_federation_index",
					step: "remove",
					err: loggableError(error),
				},
				"federation_token_index_self_heal_failed",
			);
			// Best-effort: still return 404 regardless
		}
		res.status(404).json({
			error: "federation_not_linked",
			error_description: sanitizeErrorText(`federation '${name}' tokens not found`),
		});
		return null;
	}
	return tokens;
};

/**
 * Step 10's answer: the stored token, once its type may be disclosed. The
 * handler has judged that it does not expire within the refresh buffer.
 */
export const answerStoredToken = (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	tokens: FederationTokens,
): Response => {
	const { opts, req, res, federation } = ctx;
	const { sub } = caller;

	// The type is judged before the token is read and before the success
	// is audited, so a refused disclosure is not counted as one.
	if (!mayDiscloseTokenType(tokens.tokenType)) {
		return refuseUndisclosableTokenType(ctx, caller, tokens.tokenType);
	}
	emitAuditEvent(opts.auditSink, {
		timestamp: new Date(),
		type: "federation.token.success",
		subject: sub ?? undefined,
		ip: req.ip,
		userAgent: req.get("user-agent"),
		details: { federation, refreshed: false },
	});
	const expiresIn =
		tokens.expiresAt === null
			? undefined
			: Math.max(0, Math.floor((tokens.expiresAt.getTime() - Date.now()) / 1000));
	return res.status(200).json({
		access_token: tokens.accessToken,
		token_type: BEARER_TOKEN_TYPE,
		...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
		...(tokens.scope ? { scope: tokens.scope } : {}),
	});
};
