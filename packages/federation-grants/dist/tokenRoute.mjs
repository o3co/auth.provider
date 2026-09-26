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
 * `POST /oauth/federation-grants/:grantId/token` (#593, D9–D12).
 *
 * A shell around `retrieveFederationGrantToken`, and deliberately nothing
 * more. It adds transport, authentication, serialization, correlation and
 * audit; every decision about the grant itself is core's.
 *
 * ### What this must not do
 *
 * The mistake this design expects is an "obvious" authorization check placed
 * in FRONT of core — rejecting a client with no connection allowlist, or a
 * grant whose connection an operator removed, or one carrying an
 * ineligibility marker, before the retrieval is called. Each of those reads
 * as a tightening and each changes a settled answer:
 *
 *   - a revoked grant answers 410 whether or not the client may use its
 *     connection, because the user revoking it is the more useful truth; an
 *     allowlist check in front turns that into 403, which tells a caller the
 *     grant would work if their registration changed;
 *   - a grant with an ineligibility marker still has a usable cached token,
 *     and core serves it; refusing here withholds a token nothing is wrong
 *     with.
 *
 * Nor does it retry a denial (a "helpful" second attempt can cost a second
 * upstream rotation), recompute `expires_in`, turn an unmet `min_ttl` into an
 * error, reclassify an upstream's refusal, manage locks, add a timeout that
 * abandons the retrieval's worker, delete a credential it could not read, or
 * look in another grant or in the session-bound token store.
 *
 * It does not read `lastLook` either. That is core's private orchestration.
 */
import { retrieveFederationGrantToken, } from "@o3co/auth-provider-core";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "./audit.mjs";
import { markHandlerReached } from "./denialAudit.mjs";
import { parseFederationGrantTokenRequest } from "./parse.mjs";
import { allowedConnectionsOf } from "./permission.mjs";
import { createSanitizedReporter } from "./report.mjs";
import { requestIdOf } from "./requestId.mjs";
import { serializeFederationGrantTokenResult } from "./serialize.mjs";
export function createFederationGrantTokenHandler(options) {
    const now = options.now ?? (() => new Date());
    const report = options.logger === undefined ? undefined : createSanitizedReporter(options.logger);
    return async (req, res) => {
        // From here on this handler owns the denial; the chain's exit hook stands
        // down so that one refusal is one event.
        markHandlerReached(res);
        const correlationId = requestIdOf(res);
        // Opaque: an ID is whatever created it, and imposing the acquisition
        // generator's shape on it would refuse every record a deployment seeded
        // before that generator existed.
        const matched = req.params.grantId;
        const grantId = typeof matched === "string" ? matched : "";
        const client = req.oauthClient;
        const audit = createFederationGrantAuditBridge({
            ...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
            ...(req.ip === undefined ? {} : { ip: req.ip }),
            ...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
            operation: "token",
            now,
        });
        /** A denial this route decided, before core was ever called. */
        const deny = (answer, outcome, subject) => {
            options.background.register(audit(routeDeniedEvent({
                correlationId,
                grantId,
                outcome,
                ...(client === undefined ? {} : { clientId: client.clientId }),
                ...(subject === undefined ? {} : { subject }),
            })));
            send(answer);
        };
        const send = (answer) => {
            if (answer.retryAfterSeconds !== undefined) {
                res.set("Retry-After", String(answer.retryAfterSeconds));
            }
            res.status(answer.status).json(answer.body);
        };
        // Admitted, or refused: a request let in after the drain has begun would
        // start an upstream refresh that nothing is waiting for.
        const release = options.background.admit();
        if (release === undefined) {
            deny({
                status: 503,
                body: { error: "service_unavailable", error_description: "shutting_down" },
            }, "service_unavailable/shutting_down");
            return;
        }
        try {
            const parsed = parseFederationGrantTokenRequest(req.body);
            if (!parsed.ok) {
                deny({
                    status: 400,
                    body: { error: "invalid_request", error_description: parsed.description },
                }, "invalid_request");
                return;
            }
            if (client === undefined) {
                // Unreachable through the router, which authenticates first; a
                // hand-mounted handler that forgot to is a composition error and
                // not something to answer as if the caller were anonymous.
                deny({ status: 500, body: { error: "server_error" } }, "server_error");
                return;
            }
            const result = await retrieveFederationGrantToken({
                store: options.store,
                connection: (name) => options.connections.get(name),
                refresher: options.refresher,
                grantsBoundary: options.grantsBoundary,
                now,
                limits: options.limits,
                background: (work) => options.background.register(work),
                audit,
                ...(report === undefined ? {} : { report }),
            }, {
                grantId,
                clientId: client.clientId,
                subject: parsed.value.subject,
                // Absent means nothing is allowed: a client registered before
                // offline delegation existed does not find itself opted into it.
                allowedConnections: allowedConnectionsOf(req),
                correlationId,
                ...(parsed.value.connection === undefined ? {} : { connection: parsed.value.connection }),
                ...(parsed.value.scope === undefined ? {} : { scope: parsed.value.scope }),
                ...(parsed.value.resource === undefined ? {} : { resource: parsed.value.resource }),
                ...(parsed.value.minTtlSeconds === undefined
                    ? {}
                    : { minTtlSeconds: parsed.value.minTtlSeconds }),
            });
            // Core has already audited what it decided. A second event here would
            // double every outcome in an operator's dashboard.
            send(serializeFederationGrantTokenResult(result));
        }
        catch (error) {
            // Core did not conclude, so nothing audited this — which makes it the
            // one failure the route owns.
            report?.({ during: "handler", error, grantId, correlationId });
            deny({ status: 500, body: { error: "server_error" } }, "server_error");
        }
        finally {
            release();
        }
    };
}
