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
 * A refresh the upstream did not complete, read through core's classifier: an
 * outage (`503`) or a rate limit (`429`) keeps the stored tokens for a retry;
 * only the upstream's structured `invalid_grant` ends them (`410`); anything
 * else is `500 refresh_failed`, audited.
 */

import {
	classifyFederationRefreshError,
	emitAuditEvent,
	loggableError,
} from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";

/**
 * The answer when the provider's refresh threw. On `invalid_grant` the record
 * and the link are removed, best effort, before the `410`.
 */
export const answerRefreshFailure = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	error: unknown,
): Promise<Response> => {
	const { opts, req, res, name, federation, logger } = ctx;
	const { sid, sub } = caller;

	// Core's classifier: an outage (unreachable, timeout, 5xx) is
	// `network`, a 429 is `rate_limited`, and `invalid_grant` is only
	// ever the upstream's structured verdict. Stored tokens are ended on
	// that verdict alone; an outage or rate limit keeps them for a retry.
	const classified = classifyFederationRefreshError(error);
	const { reason } = classified;
	// The projection, never the error: its cause chain can hold the
	// rotated refresh token. An unreachable upstream is this route's
	// outage (error); every other refusal is the upstream's (warn).
	if (reason === "network") {
		logger.error(
			{ federation, reason, err: loggableError(error) },
			"federation_token_upstream_unavailable",
		);
	} else {
		logger.warn(
			{ federation, reason, err: loggableError(error) },
			"federation_token_refresh_failed",
		);
	}

	if (reason === "invalid_grant") {
		// Cleanup: delete federation token + remove federation link.
		try {
			await opts.federationTokenStore.delete(sid, name);
		} catch (cleanupErr) {
			logger.warn(
				{
					federation,
					store: "federation_token",
					step: "delete",
					err: loggableError(cleanupErr),
				},
				"federation_token_cleanup_failed",
			);
		}
		try {
			await opts.sessionFederationIndex.removeFederation(sid, name);
		} catch (cleanupErr) {
			logger.warn(
				{
					federation,
					store: "session_federation_index",
					step: "remove",
					err: loggableError(cleanupErr),
				},
				"federation_token_cleanup_failed",
			);
		}
		emitAuditEvent(opts.auditSink, {
			timestamp: new Date(),
			type: "federation.token.reauthentication_required",
			subject: sub ?? undefined,
			ip: req.ip,
			userAgent: req.get("user-agent"),
			details: { federation },
		});
		return res.status(410).json({
			error: "re_authentication_required",
			error_description: "federation re-authentication required",
		});
	}

	if (reason === "rate_limited") {
		// The upstream's own wait, when it named one in whole seconds
		// (RFC 9110 §10.2.3); none is invented when it did not.
		if (classified.retryAfterSeconds !== undefined) {
			res.setHeader("Retry-After", String(classified.retryAfterSeconds));
		}
		return res.status(429).json({
			error: "rate_limited",
			error_description: "upstream IdP rate limit exceeded; retry later",
		});
	}

	if (reason === "network") {
		return res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "upstream federation provider temporarily unavailable",
		});
	}

	// reason === "unknown" — generic 500 + audit with classifier reason for SIEM.
	emitAuditEvent(opts.auditSink, {
		timestamp: new Date(),
		type: "federation.token.refresh_failed",
		subject: sub ?? undefined,
		ip: req.ip,
		userAgent: req.get("user-agent"),
		details: { federation, reason },
	});
	return res.status(500).json({
		error: "refresh_failed",
		error_description: "federation token refresh failed",
	});
};
