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
 * Whether this browser may go on with this intent now: the claim's subject and
 * the express session first, then session admission on the cookie's claim as
 * the step's action, then the flow's own conditions. Asked at
 * every step; fails closed, so a store that cannot answer is an outage, never a yes.
 * A step-up admission asks for is a refusal at every step; at connect it also
 * carries the requirement's trip.
 * The connection pin is defined here once, for the judgement and the callback alike.
 */
import { admitSession, federationGrantAuthorizationRevision, federationGrantIdentityRevision, } from "@o3co/auth-provider-core";
import { sessionIdOf } from "./browserRequest.mjs";
/** The admission action of each browser step, as the module registers it. */
export const CONNECT = "federation_grants.connect";
export const CONSENT = "federation_grants.consent";
export const CALLBACK = "federation_grants.callback";
async function admittedSession(deps, claim, action) {
    const admission = await admitSession(deps, { claim, action });
    switch (admission.outcome) {
        case "admitted":
            // No record to bind to is no session to go on with.
            return admission.session === null
                ? { outcome: "refused" }
                : { outcome: "admitted", session: admission.session };
        case "unavailable":
            return { outcome: "unavailable", store: admission.store };
        case "step_up":
            return {
                outcome: "refused",
                stepUp: { requirement: admission.requirement, page: admission.page.href },
            };
        default:
            return { outcome: "refused" };
    }
}
/**
 * Whether THIS browser may go on with THIS intent now: the cookie names the
 * intent's subject, admission admits its session as `action`, the intent is still
 * the grant's current one, the client may still use the connection, and the
 * connection is unchanged since lodging. Asked at every step, so a revocation,
 * renewal or configuration change mid-flow stops a flow that has not finished.
 */
export async function judge(options, admission, req, claim, action, intent, now) {
    if (claim.subject !== intent.subject) {
        return { ok: false, status: 403, reason: "subject_mismatch" };
    }
    const sessionId = sessionIdOf(req);
    if (sessionId === undefined) {
        return { ok: false, status: 403, reason: "reauthentication_required" };
    }
    // A session that authenticated at or before the sessions boundary may not mint a
    // consent dated after it; `authTime` never changes, so signing in again is the
    // remedy, and the distinct error lets the page say so.
    const part = await admittedSession(admission, claim, action);
    if (part.outcome === "unavailable") {
        return { ok: false, status: 503, reason: "unavailable", admissionStore: part.store };
    }
    if (part.outcome === "refused") {
        // Only connect sends a browser on a step-up trip: consent and the callback
        // come after connect has gated, and answer it as a dead session.
        return {
            ok: false,
            status: 403,
            reason: "reauthentication_required",
            ...(action === CONNECT && part.stepUp !== undefined ? { stepUp: part.stepUp } : {}),
        };
    }
    const { session } = part;
    // Which question is being asked, so that a failure names what could not answer.
    let asking = { store: "federation_grant", step: "is_current_intent" };
    try {
        if (!(await options.grantStore.isCurrentIntent(intent.grantId, intent.handle, now()))) {
            return { ok: false, status: 400, reason: "stale" };
        }
        asking = { store: "client", step: "find" };
        // The slot answers the boundary's validated copy: the allowlist is a list
        // of strings, and a record holding anything else rejects the lookup.
        const client = await options.clientRepository.findById(intent.clientId);
        const allowed = client?.allowedFederationGrantConnections ?? [];
        if (client === null || !allowed.includes(intent.connection)) {
            return { ok: false, status: 403, reason: "connection_not_permitted" };
        }
    }
    catch (error) {
        // Fails closed: a pointer or a client that cannot be read is not a yes.
        return { ok: false, status: 503, reason: "unavailable", unanswered: { ...asking, error } };
    }
    if (!pinned(options.connections.get(intent.connection), intent)) {
        // The user would be shown one thing and the upstream asked for another.
        return { ok: false, status: 400, reason: "connection_changed" };
    }
    return { ok: true, binding: { sessionId, sid: session.sid, subject: session.sub } };
}
/**
 * Whether the connection is still the one the intent was lodged against: present,
 * the same federation entry, both revisions and the callback. The name is pinned
 * because the revisions do not cover it, and boot probed the Store under the current one.
 */
export function pinned(connection, intent) {
    return (connection !== undefined &&
        connection.federation === intent.federation &&
        federationGrantIdentityRevision(connection) === intent.identityRevision &&
        federationGrantAuthorizationRevision(connection) === intent.authorizationRevision &&
        connection.callbackUri === intent.callbackUri);
}
/**
 * A judgement that could not be made, as one line: the client registry as
 * core's `client_repository_unavailable` with this route as its site, any
 * other store as the route's own outage.
 */
export const judgementUnavailable = (log, route, fields, intent, unanswered) => {
    if (unanswered.store === "client") {
        log.clientRepositoryUnavailable(`federation_grant_${route}`, intent.clientId, unanswered.error);
        return;
    }
    log.outage(`federation_grant_${route}_unavailable`, { ...fields, reason: "storage", store: unanswered.store, step: unanswered.step }, unanswered.error);
};
/**
 * Check 3, asked before the exchange and again before activation with the same
 * claim: the same express session and durable session the flow started in,
 * admitted as the callback. An outage is `"unavailable"`, already logged by
 * admission.
 */
export async function sessionHolds(admission, req, claim, transaction) {
    const { binding, intent } = transaction;
    if (!claim.authenticated)
        return "reauthentication_required";
    if (claim.subject !== intent.subject || binding.subject !== intent.subject) {
        return "account_mismatch";
    }
    if (sessionIdOf(req) !== binding.sessionId || claim.sid !== binding.sid) {
        return "reauthentication_required";
    }
    const part = await admittedSession(admission, claim, CALLBACK);
    if (part.outcome === "unavailable")
        return "unavailable";
    return part.outcome === "refused" ? "reauthentication_required" : "ok";
}
