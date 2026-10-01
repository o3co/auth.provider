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
 * A link with no record the route can serve: the link is removed from the
 * session's index, best effort, and answered `404 federation_not_linked`.
 */

import { loggableError, sanitizeErrorText } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";

/**
 * The answer for a record that is missing, or that a store judging its
 * records would have answered as missing.
 */
export const answerUnlinkedRecord = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
): Promise<Response> => {
	const { opts, res, name, federation, logger } = ctx;
	try {
		await opts.sessionFederationIndex.removeFederation(caller.sid, name);
	} catch (error) {
		// Best effort: the answer is the 404 either way.
		logger.warn(
			{
				federation,
				store: "session_federation_index",
				step: "remove",
				err: loggableError(error),
			},
			"federation_token_index_self_heal_failed",
		);
	}
	return res.status(404).json({
		error: "federation_not_linked",
		error_description: sanitizeErrorText(`federation '${name}' tokens not found`),
	});
};
