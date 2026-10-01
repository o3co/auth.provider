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
 * never answered `200`.
 */

import { BEARER_TOKEN_TYPE, canonicalScope, emitAuditEvent } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { isUsableToken } from "./federationTokenCredential.mjs";
import type { DisclosableToken } from "./federationTokenDisclosure.mjs";
import { answerUnlinkedRecord } from "./federationTokenUnlinked.mjs";

/**
 * Hands `token` to the caller; only the disclosure check produces one.
 * `expires_in` is computed last, just before the answer is sent,
 * so time spent before it (the audit call included) is not counted as lifetime left.
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
		return answerUnlinkedRecord(ctx, caller);
	}
	emitAuditEvent(opts.auditSink, {
		timestamp: new Date(),
		type: "federation.token.success",
		subject: caller.sub ?? undefined,
		ip: req.ip,
		userAgent: req.get("user-agent"),
		details: { federation, refreshed },
	});
	const expiresIn =
		token.expiresAt === null
			? undefined
			: Math.max(0, Math.floor((token.expiresAt.getTime() - Date.now()) / 1000));
	const scope = canonicalScope(token.scope);
	return res.status(200).json({
		access_token: token.accessToken,
		token_type: BEARER_TOKEN_TYPE,
		...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
		...(scope !== undefined ? { scope } : {}),
	});
};
