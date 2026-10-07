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
 * Invalidate everything this authorization server issued for one subject
 * (#296).
 *
 * The Store owns the credential-change flow — issuing the reset token,
 * delivering it, writing the new password. What it cannot do from outside is
 * kill the sessions and tokens already minted against the old credential, and
 * that is this function's whole job. The service calls it immediately after
 * the credential write.
 *
 * **The watermark is written first, before any session is cascaded.** Two
 * reasons, and both are the difference between working and not:
 *
 *   - A refresh rotation or a concurrent login on another replica can mint a
 *     token *during* the cascade loop. Enumerating sessions first and writing
 *     the watermark afterwards leaves that token outside both mechanisms —
 *     its session was not in the list, and its `iat` predates the watermark
 *     that had not yet been written.
 *   - On partial failure the safe direction is "tokens dead, some sessions
 *     perhaps alive", not the reverse. A live session with no usable token
 *     can be cleaned up on retry; a live token is the thing being revoked.
 *
 * **This never throws.** The caller has already written the new credential and
 * has no undo, so an exception would replace a partial result it could act on
 * — retry these sids, alert on that outage — with nothing at all. Every store
 * call is therefore reported rather than propagated, and `complete` is the one
 * field a caller has to check.
 *
 * Does **not** fix #276 — the local logout route still does not run the
 * cascade for its own session. This builds on `cascadeLogout`, which is
 * complete; the gap there is that one caller does not invoke it.
 */
export async function revokeAllForSubject(opts) {
    const now = opts.now ?? Date.now;
    const unavailable = [];
    const failures = [];
    // Step 1 — watermark, before anything else. See the ordering note above.
    let tokensRevoked = false;
    if (opts.subjectRevocation === undefined) {
        unavailable.push("subjectRevocation");
    }
    else {
        const at = now();
        try {
            await opts.subjectRevocation.revokeBefore(opts.subject, new Date(at), new Date(at + opts.watermarkTtlMs));
            tokensRevoked = true;
        }
        catch (error) {
            // Reported, not thrown, and the cascade below still runs: a watermark
            // that could not be written does not make the subject's sessions any
            // less worth killing, and returning here would revoke nothing at all.
            failures.push({ capability: "subjectRevocation", operation: "revokeBefore", error });
            opts.logger?.error({ err: error, subject: opts.subject }, "revoke_all_watermark_failed");
        }
    }
    // Step 2 — cascade every session the subject holds.
    const sessionsRevoked = [];
    const sessionsFailed = [];
    if (opts.subjectSessionIndex === undefined) {
        unavailable.push("subjectSessionIndex");
    }
    else {
        const index = opts.subjectSessionIndex;
        let sids = [];
        try {
            sids = await index.listSids(opts.subject);
        }
        catch (error) {
            // Nothing to enumerate means nothing to cascade, but the watermark
            // above may already be in force — which is why this is a reported
            // partial result rather than a thrown one.
            failures.push({ capability: "subjectSessionIndex", operation: "listSids", error });
            opts.logger?.error({ err: error, subject: opts.subject }, "revoke_all_list_sids_failed");
        }
        for (const sid of sids) {
            // Sequential, not concurrent: each cascade is itself a multi-store
            // sequence whose ordering matters, and a credential change is rare
            // enough that fanning out to save milliseconds is not worth the
            // extra load it would put on the same stores mid-incident.
            let ok;
            try {
                ok = (await opts.cascadeSession(sid)).ok;
            }
            catch (err) {
                opts.logger?.error({ err, subject: opts.subject, sid }, "revoke_all_cascade_failed");
                ok = false;
            }
            if (!ok) {
                // Left in the index deliberately: the entry is what a retry
                // enumerates. Removing it would strand a live session.
                sessionsFailed.push(sid);
                continue;
            }
            sessionsRevoked.push(sid);
            try {
                await index.removeSid(opts.subject, sid);
            }
            catch (error) {
                // Bookkeeping only, and deliberately not fatal to the loop: the
                // session's cascade already succeeded, so it stays counted as
                // revoked. A stale entry costs the next call one redundant
                // cascade, which is idempotent — whereas aborting here would
                // leave the subject's remaining sessions live.
                failures.push({ capability: "subjectSessionIndex", operation: "removeSid", sid, error });
                opts.logger?.error({ err: error, subject: opts.subject, sid }, "revoke_all_remove_sid_failed");
            }
        }
    }
    if (unavailable.length > 0) {
        opts.logger?.error({ subject: opts.subject, unavailable }, "revoke_all_for_subject_incomplete");
    }
    const complete = unavailable.length === 0 && failures.length === 0 && sessionsFailed.length === 0;
    return { sessionsRevoked, sessionsFailed, tokensRevoked, unavailable, failures, complete };
}
