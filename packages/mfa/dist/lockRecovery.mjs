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
 * The authorized-recovery entry: the one way the subject lock is given back
 * before its time, through core's `authorizeSubjectRecovery` and
 * `applySubjectRecovery`.
 *
 * - An authorization is minted when a factor that is not guessable (a
 *   recovery code, a passkey) verifies — at a login or a session's step-up —
 *   for that session, with a fresh 16-byte recovery id, ending
 *   `mfa.manage.maxAgeSeconds` after the verification; that lifetime is held
 *   to core's `MFA_RECOVERY_AUTHORIZATION_MAX_MS` here. A guessable factor,
 *   or a kind not installed, mints nothing.
 * - A release, in that session, reads the subjects' sessions boundary
 *   (`revokedBefore`) — none wired, none is handed — then, under the
 *   subject's lease (`factorSet.mts`), reads the subject's records and hands
 *   the store the earliest creation time of those of any kind but an
 *   installed exempt one (a record whose data does not open included, and
 *   one of a kind not installed, which may be installed again — fail-closed;
 *   a time that cannot be read as the earliest there is), and the
 *   store judges the rest in one step: whether the authorization stands,
 *   whether the boundary is later than the attack's first counted failure,
 *   and whether every guessable factor was bound after the hard hold.
 * - The answer is the store's, read for the page: `released`; `held` while
 *   the hard hold stands — never read as released; `refused` — no
 *   authorization standing (`exempt_proof_required`), the boundary not later
 *   than the attack (`not_revoked_since`), or none wired to be later
 *   (`no_revocation_boundary`); `busy`; or an outage. An authorization
 *   already applied answers what it came to, applying nothing more.
 * - `held`, and `not_revoked_since` or `no_revocation_boundary` while the
 *   hard hold stands, carry from when a rebind counts (`rebindAfter`), the store's own bound as a date;
 *   one no date can hold is the store's outage, whatever the outcome.
 * - The operator reset mints its own authorization here
 *   (`mintSubjectRecovery`) and applies it under the lease it holds across
 *   the reset (`reset.mts`).
 */
import { randomBytes } from "node:crypto";
import { MFA_RECOVERY_AUTHORIZATION_MAX_MS, } from "@o3co/auth-provider-core";
import { OUTSIDE_CONTRACT } from "./ceremony.mjs";
/**
 * Records in `store` a one-time authorization of `operation` for `subject`
 * — in session `sid` for a recover, none for a reset — under a fresh 16-byte
 * recovery id, ending `lifetimeMs` after `nowMs`. Throws what the store throws.
 */
export async function mintSubjectRecovery(store, subject, authorization) {
    await store.authorizeSubjectRecovery(subject, {
        operation: authorization.operation,
        sid: authorization.sid,
        recoveryId: randomBytes(16).toString("base64url"),
        expiresAtMs: authorization.nowMs + authorization.lifetimeMs,
    });
}
/** The earliest of `records` not of an exempt kind installed here — a kind not installed counts — `null` for none; a time that cannot be read as the earliest there is. */
const guessableBoundSince = (factors) => (records) => {
    let earliest = null;
    for (const record of records) {
        let since = 0;
        try {
            const factor = factors.get(record.kind);
            // A kind not installed may be installed again: its record counts, fail-closed.
            if (factor?.guessable === false)
                continue;
            const at = record.createdAt instanceof Date ? record.createdAt.getTime() : Number.NaN;
            since = Number.isSafeInteger(at) && at >= 0 ? at : 0;
        }
        catch {
            // A record whose fields cannot be read counts, as the earliest there is: fail-closed.
            since = 0;
        }
        earliest = earliest === null ? since : Math.min(earliest, since);
    }
    return earliest;
};
/** The hard hold an answer carries, from when a rebind counts as a date; `undefined` for a bound no date can hold. */
const hardHoldOf = (answer) => {
    if (!answer.hard)
        return null;
    const rebindAfter = new Date(answer.rebindAfterMs);
    return Number.isNaN(rebindAfter.getTime()) ? undefined : { rebindAfter };
};
/** The authorized-recovery entry over `options` (see this file's header). */
export function createMfaLockRecovery(options) {
    const { store, factorSet, factors, subjectRevocation, manageMaxAgeMs } = options;
    if (!Number.isSafeInteger(manageMaxAgeMs) ||
        manageMaxAgeMs <= 0 ||
        manageMaxAgeMs > MFA_RECOVERY_AUTHORIZATION_MAX_MS) {
        throw new RangeError(`an authorized recovery lasts mfa.manage.maxAgeSeconds, which must be a whole number of milliseconds up to core's MFA_RECOVERY_AUTHORIZATION_MAX_MS (${MFA_RECOVERY_AUTHORIZATION_MAX_MS}); it was ${String(manageMaxAgeMs)}`);
    }
    const now = options.now ?? (() => Date.now());
    const earliestGuessable = guessableBoundSince(factors);
    /** The subjects' sessions boundary as a time, `undefined` for none; an outage for one that cannot be read. */
    const boundary = async (subject) => {
        if (subjectRevocation === undefined)
            return { at: undefined };
        const outage = (cause) => ({
            outcome: "unavailable",
            store: "subject_revocation",
            step: "revokedBefore",
            cause,
        });
        let at;
        try {
            const read = await subjectRevocation.revokedBefore(subject);
            // Read inside the guard: a Date whose reads throw (a proxy, say) is the boundary's outage.
            at = read === null ? null : read instanceof Date ? read.getTime() : Number.NaN;
        }
        catch (cause) {
            return outage(cause);
        }
        if (at === null)
            return { at: undefined };
        if (!Number.isSafeInteger(at) || at < 0)
            return outage(OUTSIDE_CONTRACT);
        return { at };
    };
    /** The store's answer as the page reads it. */
    const answered = (answer) => {
        const hard = hardHoldOf(answer);
        if (hard === undefined) {
            return {
                outcome: "unavailable",
                store: "mfa_transaction",
                step: "applySubjectRecovery",
                cause: new RangeError("the store answered a rebind bound no date can hold"),
            };
        }
        switch (answer.outcome) {
            case "refused":
                switch (answer.reason) {
                    case "unauthorized":
                    case "expired":
                        return { outcome: "refused", reason: "exempt_proof_required" };
                    case "not_revoked_since":
                        return {
                            outcome: "refused",
                            reason: subjectRevocation === undefined ? "no_revocation_boundary" : "not_revoked_since",
                            rebindAfter: hard?.rebindAfter ?? null,
                        };
                    default:
                        // A boundary ahead of the clock, or a lease the store did not find held: neither is the user's to mend.
                        return {
                            outcome: "unavailable",
                            store: "mfa_transaction",
                            step: "applySubjectRecovery",
                            cause: new Error(`the store refused the release: ${answer.reason}`),
                        };
                }
            case "applied":
                return hard !== null
                    ? {
                        outcome: "held",
                        hold: "hard",
                        applied: true,
                        generation: answer.generation,
                        cleared: answer.cleared,
                        rebindAfter: hard.rebindAfter,
                    }
                    : {
                        outcome: "released",
                        applied: true,
                        generation: answer.generation,
                        cleared: answer.cleared,
                    };
            case "already_applied":
                return hard !== null
                    ? {
                        outcome: "held",
                        hold: "hard",
                        applied: false,
                        generation: answer.generation,
                        rebindAfter: hard.rebindAfter,
                    }
                    : { outcome: "released", applied: false, generation: answer.generation };
        }
    };
    return {
        async authorize(subject, sid, kind, nowMs) {
            if (factors.get(kind)?.guessable !== false)
                return { outcome: "not_exempt" };
            try {
                await mintSubjectRecovery(store, subject, {
                    operation: "recover",
                    sid,
                    nowMs,
                    lifetimeMs: manageMaxAgeMs,
                });
                return { outcome: "minted" };
            }
            catch (cause) {
                return { outcome: "unavailable", cause };
            }
        },
        async release(subject, sid) {
            const sessions = await boundary(subject);
            if ("outcome" in sessions)
                return sessions;
            // Taken after the boundary's read, which has no deadline: the store judges the boundary against it.
            const nowMs = now();
            const recovered = await factorSet.recover(subject, {
                sid,
                nowMs,
                sessionsBoundaryMs: sessions.at,
                guessableBoundSince: earliestGuessable,
            });
            return recovered.outcome === "answered" ? answered(recovered.answer) : recovered;
        },
    };
}
