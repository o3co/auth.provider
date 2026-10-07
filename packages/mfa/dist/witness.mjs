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
 * The MFA enrollment witness as this package writes it (the MFA ADR's D12):
 * `User.mfaEnrolled`, persisted by the Store through core's optional
 * `UserRepository.markMfaEnrolled`.
 *
 * - Create-then-mark: the witness is marked only after the first counting
 *   factor was written, so a crash between them leaves a factor without a
 *   witness, never a witness without a factor.
 * - Reconciliation: a verified counting factor marks a subject whose login's
 *   `User` does not say it is enrolled — at a login, or at a session's
 *   step-up, as the session recorded that `User` — so a mark that failed
 *   heals at the next login or step-up.
 * - Clear-after-remove: a removal that leaves no record that may count
 *   clears the witness once the removal is written (`management.mts`).
 * - A write that fails never undoes what it follows: the caller warns once.
 * - Read only through core's `readMfaEnrollmentWitness`.
 */
import { readMfaEnrollmentWitness, supportsMfaEnrollmentWitness, } from "@o3co/auth-provider-core";
/** The witness over `repository`; one without `markMfaEnrolled`, or none, writes nothing. */
export function createMfaEnrollmentWitness(repository) {
    const writer = repository !== undefined && supportsMfaEnrollmentWitness(repository) ? repository : undefined;
    const write = async (subject, enrolled) => {
        if (writer === undefined)
            return { outcome: "unwritable" };
        try {
            await writer.markMfaEnrolled(subject, enrolled);
            return { outcome: "marked" };
        }
        catch (cause) {
            return { outcome: "unwritten", cause };
        }
    };
    return {
        writable: writer !== undefined,
        mark: (subject) => write(subject, true),
        clear: (subject) => write(subject, false),
    };
}
/** Whether a verification of `factor` for the login's `user` marks the witness: a counting factor, a `User` not enrolled. */
export const reconciles = (factor, user) => factor.counting === true &&
    (typeof user !== "object" ||
        user === null ||
        readMfaEnrollmentWitness(user) !== "enrolled");
/**
 * Whether a verification of `factor` in a session whose login's `User`
 * carried `witness`, as the session recorded it, marks the witness: a
 * counting factor, a witness that does not say enrolled — none recorded
 * included.
 */
export const reconcilesSession = (factor, witness) => factor.counting === true && witness !== "enrolled";
/**
 * A login whose `User` says the subject enrolled — or says something
 * unreadable — while no counting factor is on record: the factor store was
 * lost or the Store answered wrongly. Never a first binding: admission
 * answers it `unavailable`, and its log line carries this as the cause.
 */
export class MfaEnrollmentStateInconsistentError extends Error {
    witness;
    reason = "mfa_enrollment_state_inconsistent";
    constructor(witness) {
        super(witness === "enrolled"
            ? "the enrollment witness says the subject enrolled, and no counting factor is on record"
            : "the enrollment witness is neither true, false nor absent");
        this.witness = witness;
        this.name = "MfaEnrollmentStateInconsistentError";
    }
}
