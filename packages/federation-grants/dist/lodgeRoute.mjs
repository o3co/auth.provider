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
 * `POST /oauth/federation-grants` and `POST /oauth/federation-grants/:grantId/reauthorize`
 * (#593, D6, slice 6) — a confidential client lodging an intent: a first grant,
 * or a renewal of one it holds.
 *
 * A shell around core's lodging, as the token route is around the retrieval. It
 * adds transport, client authentication (the router's), serialization,
 * correlation and audit, and decides nothing core decides: which connections a
 * client may use, what a redirect URI must be, which scopes an intent may ask
 * for, the lifetime, the bound, the order of the two writes, the backstop.
 *
 * What it does NOT do: look up or provision a local user — `sub` is an
 * assertion until a browser session proves it (D7) — contact the upstream,
 * create a consent, write a credential, establish a session, or activate
 * anything. The answer is where to send the user, and nothing more.
 */
import { federationGrantAuditMetadata, lodgeFederationGrantIntent, lodgeFederationGrantReauthorization, } from "@o3co/auth-provider-core";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "./audit.mjs";
import { markHandlerReached } from "./denialAudit.mjs";
import { parseFederationGrantCreateRequest, parseFederationGrantReauthorizeRequest, } from "./parse.mjs";
import { createSanitizedReporter } from "./report.mjs";
import { requestIdOf } from "./requestId.mjs";
import { serializeFederationGrantLodgingRefusal } from "./serialize.mjs";
/** Where the browser starts: the connect route, on the issuer, carrying the handle. */
export function federationGrantConnectUri(issuer, handle) {
    const base = issuer.endsWith("/") ? issuer : `${issuer}/`;
    const url = new URL("session/federation-grants/connect", base);
    url.searchParams.set("request", handle);
    return url.href;
}
const SHUTTING_DOWN = { error: "service_unavailable", error_description: "shutting_down" };
const UNEXPECTED = { error: "server_error", error_description: "unexpected_error" };
function createLodgeHandler(options, mode) {
    const now = options.now ?? (() => new Date());
    const report = options.logger === undefined ? undefined : createSanitizedReporter(options.logger);
    return async (req, res) => {
        const correlationId = requestIdOf(res);
        const matched = req.params.grantId;
        const pathGrantId = mode === "reauthorize" && typeof matched === "string" ? matched : "";
        const client = req.oauthClient;
        const audit = createFederationGrantAuditBridge({
            ...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
            ...(req.ip === undefined ? {} : { ip: req.ip }),
            ...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
            operation: "request",
            now,
        });
        markHandlerReached(res);
        /**
         * A refusal, and the trail of it. `subject` is what the caller ASSERTED
         * and `clientId` what authentication established — nothing read off a
         * record whose ownership has not been confirmed.
         */
        const deny = (status, body, outcome, subject, grantId = pathGrantId) => {
            res.status(status).json(body);
            options.background.register(audit(routeDeniedEvent({
                type: "federation.grant.request.denied",
                correlationId,
                grantId,
                outcome,
                ...(client === undefined ? {} : { clientId: client.clientId }),
                ...(subject === undefined ? {} : { subject }),
            })).catch(() => undefined));
        };
        const release = options.background.admit();
        if (release === undefined) {
            deny(503, SHUTTING_DOWN, "service_unavailable/shutting_down");
            return;
        }
        try {
            const parsed = mode === "create"
                ? parseFederationGrantCreateRequest(req.body)
                : parseFederationGrantReauthorizeRequest(req.body);
            if (!parsed.ok) {
                deny(400, { error: "invalid_request", error_description: parsed.description }, `invalid_request/${parsed.description}`);
                return;
            }
            const body = parsed.value;
            if (client === undefined) {
                // The authentication middleware answers on its own when it fails,
                // so reaching here means the chain was mounted wrongly.
                deny(500, UNEXPECTED, "server_error/unexpected_error", body.subject);
                return;
            }
            const deps = {
                grantStore: options.store,
                intentStore: options.acquisition.intentStore,
                connections: options.acquisition.connections,
                limits: options.acquisition.limits,
                now,
                grantsRevokedBefore: options.grantsBoundary,
                revocationSkewMs: options.limits.revocationSkewMs,
                maxExpiresInMs: options.limits.maxExpiresInMs,
            };
            const common = {
                client,
                subject: body.subject,
                redirectUri: body.redirectUri,
                clientState: body.clientState,
                ...(body.scope === undefined ? {} : { scopes: body.scope }),
                ...(body.expiresInSeconds === undefined
                    ? {}
                    : { requestedLifetimeMs: body.expiresInSeconds * 1000 }),
                ...(body.upstreamSubject === undefined ? {} : { upstreamSubject: body.upstreamSubject }),
                correlationId,
            };
            const result = mode === "create"
                ? await lodgeFederationGrantIntent(deps, {
                    ...common,
                    // The parser required it on this route.
                    connection: body.connection,
                })
                : await lodgeFederationGrantReauthorization(deps, {
                    ...common,
                    grantId: pathGrantId,
                    ...(body.connection === undefined ? {} : { connection: body.connection }),
                });
            if (!result.ok) {
                if (result.reason === "grant_revoked" &&
                    result.revokedNow &&
                    result.revoked !== undefined) {
                    // The backstop this renewal found, written down by this call:
                    // audited as the revocation it is, from the record the write
                    // returned — never from what the caller claimed (D18).
                    const revoked = result.revoked;
                    options.background.register(audit({
                        type: "federation.grant.revoked",
                        correlationId,
                        grantId: revoked.id,
                        clientId: client.clientId,
                        subject: revoked.subject,
                        ...federationGrantAuditMetadata(revoked),
                        outcome: "backstop",
                    }).catch(() => undefined));
                }
                if (result.reason === "storage" || result.reason === "key_unavailable") {
                    report?.({
                        during: "lodge",
                        error: new Error(result.reason),
                        grantId: pathGrantId,
                        correlationId,
                    });
                }
                const answer = serializeFederationGrantLodgingRefusal(result);
                const error = String(answer.body.error);
                const description = answer.body.error_description;
                deny(answer.status, answer.body, typeof description === "string" ? `${error}/${description}` : error, body.subject);
                return;
            }
            const at = now();
            options.background.register(audit({
                type: "federation.grant.requested",
                correlationId,
                grantId: result.grantId,
                clientId: client.clientId,
                // Asserted, not yet proven: the connect flow is where a session
                // establishes whose grant this is (D7).
                subject: body.subject,
                connection: result.connection,
                scopes: result.scopes,
                ...(result.resource === undefined ? {} : { resource: result.resource }),
                outcome: mode === "create" ? "initial" : "reauthorization",
            }).catch(() => undefined));
            res.status(201).json({
                grant_id: result.grantId,
                status: "status" in result ? result.status : "pending",
                connect_uri: federationGrantConnectUri(options.issuer, result.handle),
                // What is left of the flow's one deadline, in whole seconds — not a
                // constant: a request that took a while to answer has less.
                connect_expires_in: Math.max(0, Math.ceil((result.intentExpiresAt.getTime() - at.getTime()) / 1000)),
                // The lifetime that applied. There is no `expires_at` yet: a grant
                // is dated from the consent, which has not happened (D3).
                expires_in: Math.floor(result.lifetimeMs / 1000),
            });
        }
        catch (error) {
            report?.({ during: "handler", error, grantId: pathGrantId, correlationId });
            deny(500, UNEXPECTED, "server_error/unexpected_error");
        }
        finally {
            release();
        }
    };
}
export function createFederationGrantCreateHandler(options) {
    return createLodgeHandler(options, "create");
}
export function createFederationGrantReauthorizeHandler(options) {
    return createLodgeHandler(options, "reauthorize");
}
