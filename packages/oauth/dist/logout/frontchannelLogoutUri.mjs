/*
 * Copyright 2026 1o1 Co. Ltd.
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
import { auditErrorText, guardedRead, loggableError } from "@o3co/auth-provider-core";
const HTTP_PROTOCOLS = new Set(["http:", "https:"]);
/** One warn that cannot throw: a logger that throws costs the line, never the caller's flow. */
function warnOnce(logger, fields, event) {
    try {
        logger.warn(fields, event);
    }
    catch {
        // The line is lost; the flow goes on.
    }
}
/**
 * The URI `read` holds, when it may be used; otherwise `undefined`, a refusal
 * logged through `refuse`. `read` is `guardedRead`'s answer: `null` when the
 * read threw, kept apart from `{ value: undefined }`, an absent field.
 */
function checkedUri(read, refuse) {
    // The error is not logged: its message could carry the value.
    if (read === null)
        return refuse("unreadable");
    const value = read.value;
    if (value === undefined || value === null || value === "")
        return undefined;
    if (typeof value !== "string")
        return refuse("not-a-string");
    let protocol;
    try {
        // Parsed, never prefix-matched: the parser lowercases the scheme and
        // strips tab and newline, as a browser resolving the value does.
        protocol = new URL(value).protocol;
    }
    catch {
        return refuse("unparsable");
    }
    return HTTP_PROTOCOLS.has(protocol) ? value : refuse("not-http");
}
/** The warn for one refusal: the site, the client id and the reason, never the URI. */
const refuser = (site, clientId, logger) => (reason) => {
    warnOnce(logger, { site, clientId: auditErrorText(clientId()), reason }, "logout_frontchannel_uri_refused");
    return undefined;
};
/**
 * The RP's front-channel fields, each read once, when its URI may be used;
 * otherwise `undefined`. Absent (`undefined`, `null`, `""`) is silent.
 * Anything else must be a string whose parsed protocol is `http:` or
 * `https:`, on any host, the scheme rule core's client-record schema applies. A
 * refused value is one warn with the reason, never the value. Every read goes
 * through core's `guardedRead` and the warn is guarded: front-channel logout
 * is best-effort, so a refusal drops only this RP.
 *
 * Checked where it is used: an entry a custom session RP registry answers is
 * not read through core's client-record boundary, so nothing upstream holds
 * it to that rule. A session flag whose read throws skips the RP with one
 * `logout_frontchannel_iframe_skipped` warn, as an iframe that cannot be
 * built does. Never throws. Who renders from the answer reads nothing of the
 * RP again.
 */
export function usableFrontchannelRP(rp, site, logger) {
    const clientId = guardedRead(rp, "clientId")?.value;
    const uri = checkedUri(guardedRead(rp, "frontchannelLogoutUri"), refuser(site, () => clientId, logger));
    if (uri === undefined)
        return undefined;
    let sessionRequired;
    try {
        sessionRequired = rp.frontchannelLogoutSessionRequired;
    }
    catch (err) {
        // A flag, not the URI: its error's projection is logged, as for an iframe.
        warnOnce(logger, { clientId: auditErrorText(clientId), err: loggableError(err) }, "logout_frontchannel_iframe_skipped");
        return undefined;
    }
    return {
        clientId: typeof clientId === "string" ? clientId : "",
        frontchannelLogoutUri: uri,
        // Only an explicit `false` leaves `sid` out; anything else keeps the default.
        frontchannelLogoutSessionRequired: sessionRequired === false ? false : undefined,
    };
}
