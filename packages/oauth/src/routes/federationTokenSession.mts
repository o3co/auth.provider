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
 * Whether the caller's session is live, read from core's session lifecycle:
 * a session whose close has committed is not, nor a live session of another
 * subject. Not live is `401 invalid_token` "session not found"; an outage, or
 * any answer other than `live` or `not_live`, is `503`.
 */

import { loggableError, type SessionLiveness } from "@o3co/auth-provider-core";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";

/** Answers and returns `false` unless the caller's session is live for its `sub`. */
export const checkSessionLive = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
): Promise<boolean> => {
	const { opts, res, federation, logger } = ctx;
	const { sid, sub } = caller;
	let liveness: SessionLiveness;
	try {
		liveness = await opts.sessionLifecycle.liveness(sid);
	} catch (error) {
		// A lifecycle filled by the host may throw: an outage all the same.
		logger.error(
			{ federation, store: "session_lifecycle", step: "liveness", err: loggableError(error) },
			"federation_token_store_unavailable",
		);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		return false;
	}
	// Any answer other than `live` or `not_live` (core's lifecycle gives none,
	// as it rejects on an outage) is answered as the outage.
	if (liveness.outcome !== "live" && liveness.outcome !== "not_live") {
		logger.error(
			{ federation, store: "session_lifecycle", step: "liveness" },
			"federation_token_store_unavailable",
		);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		return false;
	}
	if (liveness.outcome === "live" && liveness.session.sub === sub) return true;
	res.setHeader(
		"WWW-Authenticate",
		'Bearer error="invalid_token", error_description="session not found"',
	);
	res.status(401).json({
		error: "invalid_token",
		error_description: "session not found",
	});
	return false;
};
