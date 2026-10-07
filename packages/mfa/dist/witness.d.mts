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
import { type MfaFactor, type UserRepository } from "@o3co/auth-provider-core";
import type { MfaCeremonySession } from "./ceremony.mjs";
/** What writing the witness — marking or clearing it — came to. */
export type MfaWitnessMark = {
    readonly outcome: "marked";
}
/** The witness says what the records do: no mark was due, or a mark was undone by a clear once the records held none that may count. */
 | {
    readonly outcome: "in_step";
}
/** The directory has no `markMfaEnrolled`: said once at boot. */
 | {
    readonly outcome: "unwritable";
} | {
    readonly outcome: "unwritten";
    readonly cause: unknown;
};
/** Writes the witness through the composition's directory, when it can. */
export interface MfaEnrollmentWitness {
    /** Whether the directory can write it (core's `supportsMfaEnrollmentWitness`). */
    readonly writable: boolean;
    /** Marks `subject` enrolled; never throws. */
    mark(subject: string): Promise<MfaWitnessMark>;
    /** Marks `subject` not enrolled; never throws. */
    clear(subject: string): Promise<MfaWitnessMark>;
}
/** The witness over `repository`; one without `markMfaEnrolled`, or none, writes nothing. */
export declare function createMfaEnrollmentWitness(repository: UserRepository | undefined): MfaEnrollmentWitness;
/** Whether a verification of `factor` for the login's `user` marks the witness: a counting factor, a `User` not enrolled. */
export declare const reconciles: (factor: MfaFactor, user: unknown) => boolean;
/**
 * Whether a verification of `factor` in a session whose login's `User`
 * carried `witness`, as the session recorded it, marks the witness: a
 * counting factor, a witness that does not say enrolled — none recorded
 * included.
 */
export declare const reconcilesSession: (factor: MfaFactor, witness: MfaCeremonySession["witness"]) => boolean;
/**
 * A login whose `User` says the subject enrolled — or says something
 * unreadable — while no counting factor is on record: the factor store was
 * lost or the Store answered wrongly. Never a first binding: admission
 * answers it `unavailable`, and its log line carries this as the cause.
 */
export declare class MfaEnrollmentStateInconsistentError extends Error {
    readonly witness: "enrolled" | "malformed";
    readonly reason = "mfa_enrollment_state_inconsistent";
    constructor(witness: "enrolled" | "malformed");
}
//# sourceMappingURL=witness.d.mts.map