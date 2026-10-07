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
 * How `/authorize` answers: the login-page redirect (also sent by the login
 * check, before any lookup) and, once `redirect_uri` is validated, an error on
 * it with `state` (RFC 6749 §4.1.2.1) and the `authorize.rejected` audit event.
 * Until then, the client stage answers JSON itself.
 */
import { emitAuditEvent, sanitizeErrorText } from "@o3co/auth-provider-core";
/** The login-page redirect with the request to come back to. */
export const loginRedirect = (res, login, target) => {
    res.redirect(login.urlFor(target));
};
// RFC 6749 §4.1.2.1: errors that prevent redirect (invalid client or
// redirect_uri) are 400 JSON; the rest redirect with error params. The same
// section limits `error_description`'s characters, and several descriptions
// echo client input, so it is sanitised here once.
export const redirectError = (ctx, error, errorDescription) => {
    const location = ctx.opts.authorizationResponse(ctx.redirectUri, { error, error_description: sanitizeErrorText(errorDescription) }, ctx.state);
    return ctx.res.redirect(location);
};
/**
 * Emits `authorize.rejected`, with the payload shape of the token endpoint's
 * `token.issued.failure`; the success event is `authorize.granted`.
 */
export const auditFailure = (ctx, details) => emitAuditEvent(ctx.opts.auditSink, {
    timestamp: new Date(),
    type: "authorize.rejected",
    clientId: ctx.clientId,
    ip: ctx.req.ip,
    userAgent: ctx.req.get("user-agent"),
    details,
});
