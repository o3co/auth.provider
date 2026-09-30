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
 * How `/authorize` answers once `redirect_uri` is validated: an error on it,
 * with `state` (RFC 6749 §4.1.2.1), the `authorize.rejected` audit event, and
 * the login-page redirect. Before that, the client stage answers JSON itself.
 */

import { emitAuditEvent, type LoginEntry, sanitizeErrorText } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { AuthorizeContext } from "./authorizeContext.mjs";

/** The login-page redirect with the request to come back to. */
export const loginRedirect = (
	res: Response,
	login: Pick<LoginEntry, "urlFor">,
	target: string,
): void => {
	res.redirect(login.urlFor(target));
};

// RFC 6749 §4.1.2.1: errors that prevent redirect (invalid client or
// redirect_uri) are 400 JSON; the rest redirect with error params. The same
// section limits `error_description`'s characters, and several descriptions
// echo client input, so it is sanitised here once.
export const redirectError = (
	ctx: AuthorizeContext,
	error: string,
	errorDescription: string,
): Response => {
	const url = new URL(ctx.redirectUri);
	url.searchParams.append("error", error);
	url.searchParams.append("error_description", sanitizeErrorText(errorDescription));
	if (typeof ctx.state === "string") url.searchParams.append("state", ctx.state);
	return ctx.res.redirect(url.toString()) as unknown as Response;
};

/**
 * Emits `authorize.rejected`, with the payload shape of the token endpoint's
 * `token.issued.failure`; the success event is `authorize.granted`.
 */
export const auditFailure = (
	ctx: AuthorizeContext,
	details: Record<string, unknown>,
): Promise<void> =>
	emitAuditEvent(ctx.opts.auditSink, {
		timestamp: new Date(),
		type: "authorize.rejected",
		clientId: ctx.clientId,
		ip: ctx.req.ip,
		userAgent: ctx.req.get("user-agent"),
		details,
	});
