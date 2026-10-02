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
 * The one success answer of the federation token route, whichever path the
 * token came by: audited as `federation.token.success`, then answered `200`
 * as `Bearer`, with the scope in its canonical form and `expires_in` omitted
 * when there is no finite expiry. A record holding no usable access token is
 * never answered `200`, nor a token with less than the refresh floor left when
 * the answer is built: that is `503`, and the client's retry refreshes it.
 */

import { BEARER_TOKEN_TYPE, canonicalScope, emitAuditEvent } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { isUsableToken } from "./federationTokenCredential.mjs";
import type { DisclosableToken } from "./federationTokenDisclosure.mjs";
import { REFRESH_FLOOR_MS } from "./federationTokenRefreshAnswer.mjs";
import { answerUnlinkedRecord } from "./federationTokenUnlinked.mjs";

/** Ms the token has left now; `undefined` with no finite expiry, NaN for an end that names no instant. */
const remainingNow = (token: DisclosableToken): number | undefined =>
	token.expiresAt === null ? undefined : token.expiresAt.getTime() - Date.now();

/** Less than the refresh floor left, or an end that names no instant (NaN fails the comparison). */
const isSpent = (remainingMs: number | undefined): boolean =>
	remainingMs !== undefined && !(remainingMs >= REFRESH_FLOOR_MS);

/** A token judged spent as its answer is built: the client's retry finds it due and refreshes it. */
const refuseSpent = (res: Response): Response =>
	res.status(503).json({
		error: "temporarily_unavailable",
		error_description: "the federation token has less than a second left; retry",
	});

/**
 * Hands `token` to the caller; only the disclosure check produces one.
 * The floor is judged before the success is audited, and again where
 * `expires_in` is computed, last, just before the answer is sent: time spent
 * before it (the audit call included) is not counted as lifetime left, and a
 * `200` never carries `expires_in: 0`.
 */
export const answerToken = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	token: DisclosableToken,
	refreshed: boolean,
): Promise<Response> => {
	const { opts, req, res, federation, logger } = ctx;
	// Answered as a store that judges its records answers such a record: as
	// none. Logged with the federation alone, never what the record holds.
	if (!isUsableToken(token.accessToken)) {
		logger.warn({ federation }, "federation_token_record_unusable");
		return answerUnlinkedRecord(ctx);
	}
	if (isSpent(remainingNow(token))) return refuseSpent(res);
	emitAuditEvent(opts.auditSink, {
		timestamp: new Date(),
		type: "federation.token.success",
		subject: caller.sub ?? undefined,
		ip: req.ip,
		userAgent: req.get("user-agent"),
		details: { federation, refreshed },
	});
	// A sink that held this turn past the floor: audited, still never handed on.
	const remainingMs = remainingNow(token);
	if (isSpent(remainingMs)) return refuseSpent(res);
	const expiresIn = remainingMs === undefined ? undefined : Math.floor(remainingMs / 1000);
	const scope = canonicalScope(token.scope);
	return res.status(200).json({
		access_token: token.accessToken,
		token_type: BEARER_TOKEN_TYPE,
		...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
		...(scope !== undefined ? { scope } : {}),
	});
};
