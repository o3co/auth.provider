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
 * and handed on as stored while they are not due for refresh.
 */

import type { FederationTokens } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { isDisclosable, refuseUndisclosableTokenType } from "./federationTokenDisclosure.mjs";
import { answerToken } from "./federationTokenSuccess.mjs";
import { answerUnlinkedRecord } from "./federationTokenUnlinked.mjs";

/**
 * Step 9: the record for this session and federation. Returns it, or `null`
 * once answered.
 */
export const readStoredTokens = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
): Promise<FederationTokens | null> => {
	const { opts, res, name, federation, storeUnavailable } = ctx;
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
		await answerUnlinkedRecord(ctx, caller);
		return null;
	}
	return tokens;
};

/**
 * Step 10's answer: the stored token, once its type may be disclosed. The
 * handler has judged that it is not due for refresh.
 */
export const answerStoredToken = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	tokens: FederationTokens,
): Promise<Response> => {
	// The type is judged before the token is read and before the success
	// is audited, so a refused disclosure is not counted as one.
	if (!isDisclosable(tokens)) {
		return refuseUndisclosableTokenType(ctx, caller, tokens.tokenType);
	}
	return answerToken(ctx, caller, tokens, false);
};
