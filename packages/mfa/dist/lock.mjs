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
 * The subject lock in the verify path (the MFA ADR's D21, F1 step 5), over
 * the transaction store's lock operations and `mfa.lockout`.
 *
 * - A guessable proof reserves one of its subject's attempts before it is
 *   checked, and settles it once. Only a factor that says it is not
 *   guessable is exempt: it reserves nothing, passes during every hold, and
 *   records an exempt success when it settles a success, which ends a run
 *   before the hard hold is fixed and never the hard hold (the store's rule,
 *   handed the policy). Each is judged at
 *   the time its verification passes, so one verification has one time.
 * - A refusal names its hold, when an attempt may come back (none for the
 *   hard hold), and whether it begins an episode.
 * - A reservation the store cannot answer, or answers outside the port
 *   (core's `readMfaSubjectAttemptReservation`), is an outage: never a pass,
 *   never a hold.
 * - Settling never throws: a settle or an exempt success the store does not
 *   take is handed to `unsettled` once, and the answer stands. The attempt
 *   it leaves pending counts as a failure.
 */
import { readMfaSubjectAttemptReservation, } from "@o3co/auth-provider-core";
import { OUTSIDE_CONTRACT, outage } from "./ceremony.mjs";
/** The subject lock over `options` (see this file's header). */
export function createMfaSubjectLock(options) {
    const { store, policy, unsettled } = options;
    /** `settle`, run once; what it throws is reported, never thrown. */
    const once = (subject, kind, step, settle) => {
        let settled = false;
        return {
            outcome: "entered",
            async settle(outcome) {
                if (settled)
                    return;
                settled = true;
                try {
                    await settle(outcome);
                }
                catch (cause) {
                    unsettled({ subject, kind, step, outcome, cause });
                }
            },
        };
    };
    return {
        async enter(subject, factor, nowMs) {
            if (factor.guessable === false) {
                return once(subject, factor.kind, "noteExemptSuccess", async (outcome) => {
                    // Called after the consume, as the port requires: a success is settled only then.
                    if (outcome === "success")
                        await store.noteExemptSuccess(subject, nowMs, policy);
                });
            }
            let answer;
            try {
                answer = await store.reserveSubjectAttempt(subject, nowMs, policy);
            }
            catch (cause) {
                return outage("mfa_transaction", "reserveSubjectAttempt", cause);
            }
            const read = readMfaSubjectAttemptReservation(answer);
            if (read === undefined) {
                return outage("mfa_transaction", "reserveSubjectAttempt", OUTSIDE_CONTRACT);
            }
            if (!read.ok) {
                return {
                    outcome: "locked",
                    hold: read.hold,
                    retryAfterMs: read.retryAfterMs,
                    first: read.first,
                };
            }
            const { reservation } = read;
            return once(subject, factor.kind, "settleSubjectAttempt", (outcome) => store.settleSubjectAttempt(subject, reservation, outcome));
        },
    };
}
/**
 * The exempt kinds `subject` holds — installed, not guessable, with at
 * least one record — each once, in code-unit order. An inventory, not a
 * verdict: whether one works shows at its verification.
 */
export function exemptKindsHeld(options) {
    const { records, factors } = options;
    const kinds = new Set(records
        .filter((record) => factors.get(record.kind)?.guessable === false)
        .map((record) => record.kind));
    return [...kinds].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
