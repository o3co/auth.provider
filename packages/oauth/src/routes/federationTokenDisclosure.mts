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
 * Whether an upstream token may be handed to the caller, and the refusal when
 * it may not: this route delegates by value, so only `Bearer` goes out; any
 * other type is `502 upstream_token_ineligible`, audited, with `Retry-After`.
 * The check alone marks a token `DisclosableToken`, the only kind the success
 * answer takes.
 */

import {
	auditErrorText,
	emitAuditEvent,
	type FederationTokens,
	isBearerTokenType,
} from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";

/**
 * Seconds a caller is asked to wait before retrying a token this route may
 * not hand on — the default of `federation-grants.ineligibleRetryAfter` on the
 * offline-delegation route. A hint against a hot loop: the condition ends
 * only when the upstream's registration changes.
 */
const UPSTREAM_INELIGIBLE_RETRY_AFTER_SECONDS = 300;

/**
 * Whether a stored upstream token may be handed to the caller. This route
 * delegates the token by value to a caller holding no proof key, so only
 * `Bearer` qualifies: every other IANA access token type is sender-constrained
 * (`PoP`, `DPoP`) or not an access token (`N_A`), as core's
 * `federation-grants/eligibility.mts` also judges.
 *
 * Only an absent field is admitted unread (RFC 6749 §5.1 requires
 * `token_type`, so silence means an adapter or record that predates carrying
 * it). Anything present is read — `null`, `""` or a number included — so a
 * malformed record never answers `Bearer`.
 */
const mayDiscloseTokenType = (stored: unknown): boolean => {
	if (stored === undefined) return true;
	return isBearerTokenType(stored);
};

declare const disclosableBrand: unique symbol;

/** A token whose type `isDisclosable` judged: nothing else produces one. */
export type DisclosableToken = Pick<FederationTokens, "accessToken" | "expiresAt" | "scope"> & {
	readonly [disclosableBrand]: true;
};

/** Whether `token` may be handed to the caller, by its type (`mayDiscloseTokenType`). */
export const isDisclosable = <
	T extends Pick<FederationTokens, "accessToken" | "expiresAt" | "scope" | "tokenType">,
>(
	token: T,
): token is T & DisclosableToken => mayDiscloseTokenType(token.tokenType);

/**
 * Refuses a token whose type this route may not delegate. `502`: what
 * came back from the upstream cannot be handed on, through no fault of
 * the caller or this provider (the offline-delegation route answers the
 * same). The named type goes to the audit sink, sanitised, not to the
 * caller. `Retry-After` because the condition is not transient.
 */
export const refuseUndisclosableTokenType = (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	named: unknown,
): Response => {
	const { opts, req, res, federation } = ctx;
	const { sub } = caller;
	emitAuditEvent(opts.auditSink, {
		timestamp: new Date(),
		type: "federation.token.upstream_ineligible",
		subject: sub ?? undefined,
		ip: req.ip,
		userAgent: req.get("user-agent"),
		details: {
			federation,
			reason: "token_type_unsupported",
			tokenType: typeof named === "string" ? auditErrorText(named) : null,
		},
	});
	res.setHeader("Retry-After", String(UPSTREAM_INELIGIBLE_RETRY_AFTER_SECONDS));
	return res.status(502).json({
		error: "upstream_token_ineligible",
		error_description: "token_type_unsupported",
	});
};
