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
import { federationGrantCorrelationId, revokeFederationGrant, } from "../federation-grants/revoke.mjs";
import { hasFederationGrantAuthorization } from "../federation-grants/types.mjs";
import { cascadeSubjectSessions } from "./cascadeSubjectSessions.mjs";
import { revokeAllForSubject, } from "./revokeAllForSubject.mjs";
import { supportsSessionsOnlyRevocation, } from "./types.mjs";
/**
 * Wiring errors are refused here, once, rather than answered per request.
 *
 * An operator who turned the allowance on and got a full revocation on every
 * call would read the outcome as the policy working — `"keep"` is precisely
 * the mode whose failure looks like success from the outside. So an adapter
 * that cannot stamp the two boundaries separately is a refusal at
 * construction, where a composition error belongs.
 */
export function createSubjectRevocationService(deps) {
    if (!Number.isFinite(deps.watermarkTtlMs) || deps.watermarkTtlMs <= 0) {
        throw new RangeError(`the subject revocation service needs a positive watermark TTL in milliseconds, and was given ${String(deps.watermarkTtlMs)}. ` +
            "Size it with resolveSubjectRevocationHorizonMs: a boundary that expires before the credentials it covers is not a backstop.");
    }
    const revocation = deps.subjectRevocation;
    if (deps.allowKeep && (revocation === undefined || !supportsSessionsOnlyRevocation(revocation))) {
        throw new TypeError(`federationGrants.allowKeepOnSubjectRevocation is on, but the subjectRevocation adapter (kind "${revocation?.kind ?? "absent"}") ` +
            "cannot stamp a sessions-only boundary: keeping a subject's federation grants needs revokeSessionsBefore and " +
            "grantsRevokedBefore. Without them every keep would silently revoke, which reads like the policy working.");
    }
    const now = deps.now ?? Date.now;
    return {
        async revokeAllForSubject(request) {
            const since = request.revokeGrantsConsentedSince;
            if (since !== undefined && Number.isNaN(since.getTime())) {
                // Before the first write, deliberately: a subject revocation
                // that stamped the boundary and then refused the argument would
                // have done the irreversible half of a call the caller was told
                // did not happen.
                throw new RangeError("revokeGrantsConsentedSince must be a valid Date");
            }
            const requested = request.federationGrants ?? "revoke";
            const applied = requested === "keep" && deps.allowKeep ? "keep" : "revoke";
            const federationGrants = requested === applied
                ? { requested, applied }
                : { requested, applied, reason: "keep_not_allowed" };
            // One correlation ID per call, on either path (#618): the service's
            // own, when it was composed with one, and otherwise this call's.
            const correlationId = federationGrantCorrelationId(deps.correlationId);
            if (applied === "revoke") {
                const result = await revokeAllForSubject({
                    subject: request.subject,
                    watermarkTtlMs: deps.watermarkTtlMs,
                    cascadeSession: deps.cascadeSession,
                    subjectSessionIndex: deps.subjectSessionIndex,
                    subjectRevocation: revocation,
                    federationGrantStore: deps.federationGrantStore,
                    federationGrantAudit: deps.federationGrantAudit,
                    correlationId,
                    logger: deps.logger,
                    now,
                });
                return { ...result, grantsRetired: [], grantsRetireFailed: [], federationGrants };
            }
            // Narrowed by the construction refusal above: `allowKeep` is what
            // admits this path, and it is refused without a capable adapter.
            return {
                ...(await keep(deps, revocation, now, request.subject, since, correlationId)),
                federationGrants,
            };
        },
    };
}
/**
 * Sessions and tokens end; established grants stay.
 *
 * The order is the one the full revocation makes, and for the same reason: the
 * boundary is written before anything is enumerated, so a session or a token
 * minted while this runs is covered by something. What differs is only which
 * boundary — `revokeSessionsBefore` moves the sessions one and leaves the
 * grants one exactly where it was. That is what makes "keep" a decision rather
 * than a race: a grant covered by an earlier full revocation stays covered,
 * because this never moves that boundary backwards.
 */
async function keep(deps, revocation, now, subject, since, correlationId) {
    const failures = [];
    const unavailable = [];
    const at = now();
    let tokensRevoked = false;
    try {
        await revocation.revokeSessionsBefore(subject, new Date(at), new Date(at + deps.watermarkTtlMs));
        tokensRevoked = true;
    }
    catch (error) {
        failures.push({
            capability: "subjectRevocation",
            operation: "revokeSessionsBefore",
            error,
        });
        deps.logger?.error({ err: error, subject }, "revoke_all_watermark_failed");
    }
    let sessions = { revoked: [], failed: [], failures: [] };
    if (deps.subjectSessionIndex === undefined) {
        unavailable.push("subjectSessionIndex");
    }
    else {
        sessions = await cascadeSubjectSessions({
            subject,
            index: deps.subjectSessionIndex,
            cascadeSession: deps.cascadeSession,
            logger: deps.logger,
        });
        failures.push(...sessions.failures);
    }
    const grantsRevoked = [];
    const grantsFailed = [];
    const grantsRetired = [];
    const grantsRetireFailed = [];
    const store = deps.federationGrantStore;
    if (store !== undefined) {
        const grantDeps = {
            store,
            now: () => new Date(now()),
            audit: deps.federationGrantAudit,
            correlationId,
        };
        let grants = [];
        try {
            grants = await store.listBySubject(subject, new Date(now()));
        }
        catch (error) {
            failures.push({ capability: "federationGrantStore", operation: "listBySubject", error });
            deps.logger?.error({ err: error, subject }, "revoke_all_list_grants_failed");
        }
        for (const grant of grants) {
            if (grant.status === "revoked")
                continue;
            // A grant with no authorization is a consent in flight, and keeping
            // what the subject established is not keeping what they had not
            // finished agreeing to. One the operator dated as compromised goes
            // the same way.
            const end = !hasFederationGrantAuthorization(grant) ||
                (since !== undefined && grant.consent.at.getTime() >= since.getTime());
            try {
                if (end) {
                    const written = await revokeFederationGrant(grantDeps, grant.id, "subject");
                    if (written.ok)
                        grantsRevoked.push(grant.id);
                    continue;
                }
                // The grant stays. Its renewal does not: a reauthorization
                // somebody walked the subject into would widen the very grant
                // this call froze, and by now the pointer is the only part of
                // it this provider can still reach (D13). No handle — whichever
                // intent is current is the one to end.
                const written = await store.retireIntent({ grantId: grant.id, now: new Date(now()) });
                // `ok: false` is a grant that had no renewal in flight. Nothing
                // to end is not a failure to end something.
                if (written.ok)
                    grantsRetired.push(grant.id);
            }
            catch (error) {
                // Counted against `complete`, both of them: reporting a
                // completed revocation while a renewal somebody else started is
                // still current would be the wrong half of the truth. Which
                // list they land in decides what a retry should DO — revoke
                // again, or retire again — so they are not one list.
                (end ? grantsFailed : grantsRetireFailed).push(grant.id);
                failures.push({
                    capability: "federationGrantStore",
                    operation: end ? "revoke" : "retireIntent",
                    grantId: grant.id,
                    error,
                });
                deps.logger?.error({ err: error, subject, grantId: grant.id }, end ? "revoke_all_revoke_grant_failed" : "revoke_all_retire_intent_failed");
            }
        }
    }
    return {
        sessionsRevoked: sessions.revoked,
        sessionsFailed: sessions.failed,
        tokensRevoked,
        grantsRequested: store !== undefined,
        grantsRevoked,
        grantsFailed,
        grantsRetired,
        grantsRetireFailed,
        unavailable,
        failures,
        complete: unavailable.length === 0 && failures.length === 0 && sessions.failed.length === 0,
    };
}
