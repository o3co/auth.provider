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
 * Lodging an intent (#593, D6, D16, slice 6): the one place that orders the two
 * writes an acquisition makes, and the rules a backend's request is held to
 * before either is made.
 *
 * ## The order, and why it is this one
 *
 * 1. the intent store admits the intent — reserving its place against the
 *    bound;
 * 2. the grant store creates the `pending` grant naming it, or names it on the
 *    existing grant being renewed.
 *
 * Intent first, because the bound is the only admission control in front of
 * `createPending`. The other way round, every refused admission would already
 * have left a pending record behind, and the bound would cap nothing.
 *
 * What an interruption leaves:
 *
 * - after the first write, before the second: an orphan intent. It cannot pass
 *   `isCurrentIntent` — no grant names it — so it activates nothing, and it
 *   lapses with its deadline;
 * - a second write the store refused: the intent is closed, so nothing can
 *   reach it through a consent;
 * - a second write whose answer was lost: asked, not assumed.
 *   `isCurrentIntent` says whether it landed, and a write that landed is kept —
 *   undoing it would destroy a flow that may already be in front of the user.
 *   A `false` is never a reason to name the handle again: `nameIntent` is not
 *   safely retryable once a newer intent may have superseded this one.
 *
 * ## What it does not do
 *
 * It contacts no upstream, creates no consent, writes no credential, looks up
 * or provisions no local user, and establishes no session. `sub` is an
 * assertion here; the connect flow is what proves it (D7).
 */
import { randomBytes } from "node:crypto";
import { checkRedirectUri } from "../net/redirect-uri.mjs";
import { federationGrantAllowlist } from "./allowlist.mjs";
import { effectiveFederationGrantStatus } from "./effective-status.mjs";
import { resolveFederationGrantIntentScopes } from "./eligibility.mjs";
import { FEDERATION_GRANT_FLOW_BUDGET_MS, } from "./intentStore.mjs";
import { resolveFederationGrantLifetimeMs } from "./lifetime.mjs";
import { federationGrantAuthorizationRevision, federationGrantIdentityRevision, } from "./revision.mjs";
/**
 * The result parameters the end of a flow appends to a client's redirect URI.
 * One the registered URI already carries would reach the client twice — once
 * as the client wrote it, once as this provider did — and which a client reads
 * is its framework's choice, not a contract.
 */
const RESERVED_RESULT_PARAMETERS = ["grant_id", "state", "error"];
/**
 * The reserved result parameter a redirect URI already carries, if any.
 *
 * Exported so that where the URI is REGISTERED can refuse it too — at boot, for
 * a deployment whose clients are configured — and lodging keeps refusing it as
 * the belt for a repository that validates nothing.
 */
export function federationGrantRedirectUriReservedParameter(uri) {
    let parsed;
    try {
        parsed = new URL(uri);
    }
    catch {
        return undefined;
    }
    return RESERVED_RESULT_PARAMETERS.find((name) => parsed.searchParams.has(name));
}
const defaultRandomId = () => randomBytes(32).toString("base64url");
/**
 * What a first intent and a renewal are held to alike: where the browser goes
 * back to, what may be asked, and for how long. The connection has already been
 * chosen — by name for a first intent, from the grant for a renewal.
 */
function checkRequest(deps, request, connection) {
    // Read as a list or as nothing (`federationGrantAllowlist`): a repository
    // answering a string would otherwise match by substring.
    const registered = federationGrantAllowlist(request.client.federationGrantRedirectUris);
    // Exact membership, and nothing else: no prefix, no normalization, no
    // fallback to the client's ordinary redirect URIs.
    if (!registered.includes(request.redirectUri)) {
        return { ok: false, reason: "redirect_uri_not_registered" };
    }
    // Registered, and still held to what registration would have refused: a
    // repository that validates nothing could hand back a URI that does not
    // parse, and the flow would fail only at its end — after activating the
    // grant — when the browser has to be sent there (the adversarial review).
    if (checkRedirectUri(request.redirectUri) !== null) {
        return { ok: false, reason: "redirect_uri_invalid" };
    }
    if (federationGrantRedirectUriReservedParameter(request.redirectUri) !== undefined) {
        return { ok: false, reason: "redirect_uri_reserved_parameter" };
    }
    const scopes = resolveFederationGrantIntentScopes(request.scopes, connection);
    if (!scopes.ok) {
        switch (scopes.reason) {
            case "outside_connection":
                return { ok: false, reason: "scope_exceeded" };
            case "subsets_not_allowed":
                return { ok: false, reason: "scope_subsets_not_allowed" };
            case "required_scope_missing": {
                const asked = new Set(request.scopes ?? []);
                return {
                    ok: false,
                    reason: asked.has("openid") ? "offline_access_required" : "openid_required",
                };
            }
        }
    }
    const requested = request.requestedLifetimeMs;
    if (requested !== undefined && !(Number.isSafeInteger(requested) && requested > 0)) {
        return { ok: false, reason: "expires_in_out_of_range" };
    }
    const lifetimeMs = resolveFederationGrantLifetimeMs({
        ...(requested !== undefined ? { requestedMs: requested } : {}),
        defaultMs: deps.limits.defaultLifetimeMs,
        maxMs: deps.limits.maxLifetimeMs,
    });
    return { ok: true, scopes: scopes.scopes, lifetimeMs };
}
const permits = (client, connection) => federationGrantAllowlist(client.allowedFederationGrantConnections).includes(connection);
function intentRecord(input) {
    const { request, connection } = input;
    return {
        handle: input.handle,
        kind: input.kind,
        grantId: input.grantId,
        clientId: request.client.clientId,
        subject: request.subject,
        connection: connection.name,
        federation: connection.federation,
        identityRevision: federationGrantIdentityRevision(connection),
        authorizationRevision: federationGrantAuthorizationRevision(connection),
        callbackUri: connection.callbackUri,
        scopes: [...input.scopes],
        ...(connection.resource !== undefined ? { resource: connection.resource } : {}),
        authorizationParams: { ...(connection.authorizationParams ?? {}) },
        redirectUri: request.redirectUri,
        clientState: request.clientState,
        ...(request.upstreamSubject !== undefined ? { upstreamSubject: request.upstreamSubject } : {}),
        lifetimeMs: input.lifetimeMs,
        createdAt: input.now,
        expiresAt: new Date(input.now.getTime() + FEDERATION_GRANT_FLOW_BUDGET_MS),
        correlationId: request.correlationId,
    };
}
async function admit(store, record, now) {
    let written;
    try {
        written = await store.putIntent(record, now);
    }
    catch {
        return { ok: false, reason: "storage" };
    }
    if (written.outcome !== "refused")
        return { ok: true };
    // A fresh 256-bit handle that collides, or a deadline ten minutes out that
    // has already passed, is a fault on this side and not the client's.
    return { ok: false, reason: written.reason === "limit" ? "intent_limit" : "storage" };
}
/** Ends an intent nothing will ever reach. Best effort: its deadline ends it anyway. */
async function close(store, handle, now) {
    try {
        await store.finishIntent(handle, now);
    }
    catch {
        // The intent cannot activate anything without a grant naming it, and it
        // lapses with the flow budget. Failing the request over its cleanup would
        // report an outage for something already harmless.
    }
}
/**
 * Lodges a first-time intent: validates what the client asked for, admits the
 * intent, and creates the `pending` grant that names it (D6, D16).
 */
export async function lodgeFederationGrantIntent(deps, request) {
    const now = deps.now ?? (() => new Date());
    const randomId = deps.randomId ?? defaultRandomId;
    // Permission before existence: which connections a deployment has is not
    // something a client may probe for.
    if (!permits(request.client, request.connection)) {
        return { ok: false, reason: "connection_not_permitted" };
    }
    const connection = deps.connections.get(request.connection);
    if (connection === undefined)
        return { ok: false, reason: "connection_not_configured" };
    const checked = checkRequest(deps, request, connection);
    if (!checked.ok)
        return checked;
    const grantId = randomId();
    const handle = randomId();
    const lodgedAt = now();
    const record = intentRecord({
        handle,
        kind: "initial",
        grantId,
        request,
        connection,
        scopes: checked.scopes,
        lifetimeMs: checked.lifetimeMs,
        now: lodgedAt,
    });
    const admitted = await admit(deps.intentStore, record, lodgedAt);
    if (!admitted.ok)
        return admitted;
    const created = await secondWrite(() => deps.grantStore.createPending({
        id: grantId,
        subject: request.subject,
        clientId: request.client.clientId,
        connection: connection.name,
        intent: { handle, expiresAt: record.expiresAt },
        now: now(),
    }), () => deps.grantStore.isCurrentIntent(grantId, handle, now()));
    if (!created) {
        await close(deps.intentStore, handle, now());
        return { ok: false, reason: "storage" };
    }
    return {
        ok: true,
        grantId,
        handle,
        intentExpiresAt: record.expiresAt,
        lifetimeMs: checked.lifetimeMs,
        connection: connection.name,
        scopes: record.scopes,
        ...(record.resource === undefined ? {} : { resource: record.resource }),
    };
}
/**
 * The grant-store write, with its answer asked for rather than assumed when it
 * was lost. `true` only when the write is known to have landed.
 */
async function secondWrite(write, landed) {
    try {
        return (await write()).ok;
    }
    catch {
        try {
            return await landed();
        }
        catch {
            return false;
        }
    }
}
/**
 * Lodges a renewal of an existing grant (D6): ownership, then the revocation
 * backstop before anything else is asked of it (D13), then what a renewal can
 * and cannot mend, then the client's current permission and its request — and
 * only then the two writes.
 */
export async function lodgeFederationGrantReauthorization(deps, request) {
    const now = deps.now ?? (() => new Date());
    const randomId = deps.randomId ?? defaultRandomId;
    let inspection;
    try {
        inspection = await deps.grantStore.inspect(request.grantId, now());
    }
    catch {
        return { ok: false, reason: "storage" };
    }
    // One answer for an unknown grant, another client's and another subject's:
    // a grant ID proves nothing, and whose grant it is must not be learnable
    // from how the refusal reads.
    if (inspection === null ||
        inspection.grant.clientId !== request.client.clientId ||
        inspection.grant.subject !== request.subject) {
        return { ok: false, reason: "grant_not_found" };
    }
    let boundary;
    try {
        boundary = await deps.grantsRevokedBefore(request.subject);
        if (boundary !== null && !(boundary instanceof Date && !Number.isNaN(boundary.getTime()))) {
            throw new TypeError("the grants boundary is neither a date nor null");
        }
    }
    catch {
        // Fails closed: a boundary that cannot be read is not "nothing revoked".
        return { ok: false, reason: "storage" };
    }
    return await judgeAndLodge(deps, request, inspection, boundary, now, randomId);
}
/** The grant's effective status, as a reauthorization judges it. */
function statusOf(deps, inspection, boundary, at) {
    return effectiveFederationGrantStatus(inspection.grant, {
        now: at,
        connection: deps.connections.get(inspection.grant.connection),
        maxExpiresInMs: deps.maxExpiresInMs,
        grantsBoundary: boundary,
        revocationSkewMs: deps.revocationSkewMs,
        credentials: inspection.credentials === "ok" ? "ok" : "unreadable",
    });
}
/**
 * What a reauthorization cannot mend, as the answer it gets — or the status it
 * is admitted from, for what D6 admits: `active`, `reauthorization_required`,
 * and (#616) a grant starved of scope. An IdP that accumulates consent answers
 * a narrower grant's refresh with a wider grant's scopes, and a wider consent
 * is exactly the remedy; the other ineligibilities — a lifetime, a type, a
 * shape no consent changes — are refused as ever, and judged as they read
 * NOW, not as a marker was left: a maximum no token can satisfy outranks an
 * old scope marker. The admitted status is what the 201 reports, unchanged.
 */
function admission(status) {
    switch (status.status) {
        case "revoked":
            return {
                refused: {
                    ok: false,
                    reason: "grant_revoked",
                    revokedBy: status.reason,
                    revokedNow: false,
                },
            };
        case "pending":
            return { refused: { ok: false, reason: "authorization_pending" } };
        case "expired":
            return { refused: { ok: false, reason: "grant_expired", expiredBy: status.reason } };
        case "connection_not_configured":
            return { refused: { ok: false, reason: "connection_not_configured" } };
        case "connection_identity_changed":
            return { refused: { ok: false, reason: "connection_identity_changed" } };
        case "upstream_token_ineligible":
            return status.reason === "scope_exceeded"
                ? { admitted: "upstream_token_ineligible" }
                : {
                    refused: {
                        ok: false,
                        reason: "upstream_token_ineligible",
                        ineligibleBy: status.reason,
                    },
                };
        case "active":
        case "reauthorization_required":
            return { admitted: status.status };
    }
}
async function judgeAndLodge(deps, request, inspection, boundary, now, randomId) {
    const { grant } = inspection;
    const status = statusOf(deps, inspection, boundary, now());
    if (status.status === "revoked" && status.reason === "backstop" && grant.status !== "revoked") {
        // Written down, not only reported: a revocation that lived only in the
        // comparison would vanish the day the boundary is lost.
        let written;
        try {
            written = await deps.grantStore.revoke(grant.id, "backstop", now());
        }
        catch {
            return { ok: false, reason: "storage" };
        }
        return written.ok
            ? {
                ok: false,
                reason: "grant_revoked",
                revokedBy: "backstop",
                revokedNow: true,
                revoked: written.grant,
            }
            : { ok: false, reason: "grant_revoked", revokedBy: "backstop", revokedNow: false };
    }
    const judged = admission(status);
    if ("refused" in judged)
        return judged.refused;
    if (status.status === "reauthorization_required" &&
        status.reason === "credential_unreadable" &&
        inspection.credentials === "key_unavailable") {
        // A key missing from the ring is an outage, not a reason to send the user
        // to consent again.
        return { ok: false, reason: "key_unavailable" };
    }
    // Defined here: a connection that is not configured was refused above.
    const connection = deps.connections.get(grant.connection);
    if (request.connection !== undefined && request.connection !== grant.connection) {
        return { ok: false, reason: "connection_mismatch" };
    }
    if (!permits(request.client, connection.name)) {
        return { ok: false, reason: "connection_not_permitted" };
    }
    const checked = checkRequest(deps, request, connection);
    if (!checked.ok)
        return checked;
    const handle = randomId();
    const lodgedAt = now();
    const record = intentRecord({
        handle,
        kind: "reauthorization",
        grantId: grant.id,
        request,
        connection,
        scopes: checked.scopes,
        lifetimeMs: checked.lifetimeMs,
        now: lodgedAt,
    });
    const admitted = await admit(deps.intentStore, record, lodgedAt);
    if (!admitted.ok)
        return admitted;
    const named = await secondWrite(() => deps.grantStore.nameIntent({
        grantId: grant.id,
        intent: { handle, expiresAt: record.expiresAt },
        now: now(),
    }), () => deps.grantStore.isCurrentIntent(grant.id, handle, now()));
    if (named) {
        return {
            ok: true,
            grantId: grant.id,
            handle,
            intentExpiresAt: record.expiresAt,
            lifetimeMs: checked.lifetimeMs,
            connection: connection.name,
            scopes: record.scopes,
            ...(record.resource === undefined ? {} : { resource: record.resource }),
            status: judged.admitted,
        };
    }
    await close(deps.intentStore, handle, now());
    // The pointer write lost: the grant changed under this request. What it is
    // NOW is the answer — never a retry on the strength of the stale reading,
    // which could renew a grant revoked in between.
    let fresh;
    try {
        fresh = await deps.grantStore.inspect(grant.id, now());
    }
    catch {
        return { ok: false, reason: "storage" };
    }
    if (fresh === null)
        return { ok: false, reason: "grant_not_found" };
    // Still renewable: the write lost to something that left it so, and the
    // honest answer is that this attempt did not take.
    const again = admission(statusOf(deps, fresh, boundary, now()));
    return "refused" in again ? again.refused : { ok: false, reason: "storage" };
}
