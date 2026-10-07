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
 * What every stage of the browser flow is handed: the router's options, and what
 * is derived from them once — the clock, the random ids, the log, admission's
 * dependencies for one request, and the audit of a failed flow. Admission's audit
 * writes and the failure audit are registered with the shutdown drain.
 */
import { randomBytes } from "node:crypto";
import { recordAuditEvent, } from "@o3co/auth-provider-core";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "./audit.mjs";
import { createFederationGrantLog } from "./log.mjs";
import { requestIdOf } from "./requestId.mjs";
/** The browser half selects no `acr`: nothing asks for one here. */
const NO_ACR_TABLE = Object.freeze({});
/**
 * Throws where a user-session store is wired without the session lifecycle
 * port: admission would skip the lifecycle record, and a closing session
 * could connect.
 */
export function requireSessionLifecycleStore(deps) {
    if (deps.userSessionStore !== undefined && deps.sessionLifecycleStore === undefined) {
        throw new Error("federation-grants: userSessionStore is wired, but sessionLifecycleStore is not. Where a " +
            "user-session store is wired, core's session lifecycle is required: the connect flow " +
            "admits the session behind the cookie through its lifecycle record. Wire core's " +
            "session lifecycle: a session-store module that fills sessionLifecycleStore " +
            "(memorySessionStoresModule or redisSessionStoresModule) and sessionLifecycleModule.");
    }
}
/**
 * The flow's shared part, derived once. `requirements` and `subjectRevocation` are
 * the ones the router has already checked.
 */
export function createBrowserFlow(options, requirements, subjectRevocation) {
    const now = options.now ?? (() => new Date());
    const randomId = options.randomId ?? (() => randomBytes(32).toString("base64url"));
    const log = createFederationGrantLog(options.logger);
    /**
     * The deployment's audit sink with every write registered with the drain, so a
     * shutdown also waits for the events admission records.
     */
    const auditSink = options.auditSink;
    const drainedAuditSink = auditSink === undefined
        ? undefined
        : {
            kind: auditSink.kind,
            record: (event) => {
                // Through core's `recordAuditEvent`, the one writer of a sink.
                const written = recordAuditEvent(auditSink, event);
                options.background.register(written.catch(() => undefined));
                return written;
            },
        };
    /**
     * Admission's dependencies for one request: its logger is bound to the flow's
     * grant, the request's correlation id and (at the consent) its method, so an
     * outage line admission writes carries them too.
     */
    const admissionFor = (flow) => ({
        userSessionStore: options.userSessionStore,
        subjectRevocation,
        sessionLifecycleStore: options.sessionLifecycleStore,
        requirements,
        acrTable: NO_ACR_TABLE,
        logger: log.bound(flow),
        auditSink: drainedAuditSink,
        now,
    });
    const auditFor = (req) => createFederationGrantAuditBridge({
        ...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
        ...(req.ip === undefined ? {} : { ip: req.ip }),
        ...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
        operation: "connect",
        now,
    });
    /** `federation.grant.authorization_failed`, with only what is established. */
    const failed = (req, res, outcome, intent) => {
        options.background.register(auditFor(req)(routeDeniedEvent({
            type: "federation.grant.authorization_failed",
            // The FLOW's id once its intent is known — the one the lodging
            // request carried, so that every event of one flow correlates.
            // Before that there is only this request's own.
            correlationId: intent?.correlationId ?? requestIdOf(res),
            // An early failure has no grant to name, and none is invented.
            grantId: intent?.grantId ?? "",
            outcome,
            ...(intent === undefined
                ? {}
                : {
                    clientId: intent.clientId,
                    subject: intent.subject,
                    connection: intent.connection,
                }),
        })).catch(() => undefined));
    };
    return { options, now, randomId, log, admissionFor, auditFor, failed };
}
