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
 * as `Bearer`, with `expires_in` omitted when there is no finite expiry.
 */

import { BEARER_TOKEN_TYPE, emitAuditEvent, type FederationTokens } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";

/**
 * Hands `token` to the caller, whose type the path has already judged
 * disclosable. `expires_in` is computed after the audit, which runs the sink
 * synchronously, so it never overstates the lifetime left when the answer goes.
 */
export const answerToken = (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	token: Pick<FederationTokens, "accessToken" | "expiresAt" | "scope">,
	refreshed: boolean,
): Response => {
	const { opts, req, res, federation } = ctx;
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
	return res.status(200).json({
		access_token: token.accessToken,
		token_type: BEARER_TOKEN_TYPE,
		...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
		...(token.scope ? { scope: token.scope } : {}),
	});
};
