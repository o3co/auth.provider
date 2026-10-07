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
import { createFederationGrantAuditBridge, routeDeniedEvent, } from "./audit.mjs";
import { requestIdOf } from "./requestId.mjs";
/** Set by the handler, so its own denial is not counted twice. */
const HANDLED = Symbol.for("o3co.federationGrants.handlerReached");
/** Called by a handler: from here on, the denial is the handler's to emit. */
export function markHandlerReached(res) {
    res[HANDLED] = true;
}
const reached = (res) => res[HANDLED] === true;
/**
 * The fixed outcome for a refusal, from the error code the middleware wrote.
 *
 * `error_description` is deliberately not read: the shared middleware puts a
 * limiter's or a repository's message there, and this is an audit trail.
 */
const outcomeOf = (status, body) => {
    const error = body?.error;
    switch (error) {
        case "invalid_client":
            return "invalid_client";
        case "rate_limited":
            return "rate_limited/provider";
        case "service_unavailable":
            return "service_unavailable/rate_limiter";
        case "invalid_request":
            return "invalid_request";
        default:
            return status >= 500 ? "server_error" : "invalid_request";
    }
};
/**
 * The hook, for one route.
 *
 * `operation` decides which event a refusal becomes: the token route's
 * denials and the revoke route's are counted separately, because a credential
 * that was not handed out and a credential that is still live are opposite
 * facts.
 */
export function createRouteDenialAudit(options) {
    const type = options.operation === "revoke"
        ? "federation.grant.revoke.denied"
        : options.operation === "request"
            ? "federation.grant.request.denied"
            : "federation.grant.token.denied";
    return (req, res, next) => {
        const correlationId = requestIdOf(res);
        const matched = req.params.grantId;
        const grantId = typeof matched === "string" ? matched : "";
        const audit = createFederationGrantAuditBridge({
            ...options,
            ...(req.ip === undefined ? {} : { ip: req.ip }),
            ...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
        });
        // The written body, kept so the outcome can be read off the error code.
        let written;
        const json = res.json.bind(res);
        res.json = (value) => {
            written = value;
            return json(value);
        };
        res.on("finish", () => {
            if (reached(res) || res.statusCode < 400)
                return;
            options.background.register(audit(routeDeniedEvent({
                type,
                correlationId,
                grantId,
                outcome: outcomeOf(res.statusCode, written),
            })).catch(() => undefined));
        });
        next();
    };
}
