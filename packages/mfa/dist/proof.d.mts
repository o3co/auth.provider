/**
 * The account-email proof before a first binding (the MFA ADR's D24, F3
 * step 2, D21's 80-bit row), named by `factor_id: "account-email"` on the
 * challenge and verify routes of a transaction whose `emailProof` is
 * `required`, and on no other: a login's, or an `enroll` one a session's
 * step-up opened.
 *
 * - The challenge mails a long code (`codes.mts`) through `sendMfaMail` to
 *   the login's address — the continuation's `User`, or the one the session's
 *   cookie holds — never a later read. The code lives ten minutes, capped at
 *   the transaction's expiry, and is kept only as a keyed digest over the
 *   transaction id and the code, sealed on the transaction; a resend replaces
 *   it. A proof nobody can give — no sender, no address — is refused, never
 *   skipped.
 * - A verification reserves one of the transaction's attempts, never a
 *   subject's: an 80-bit code is not guessed, and a lock would let a
 *   password holder lock an unenrolled account out. The code stands across
 *   attempts until it is replaced or proved; past the transaction's attempts
 *   the transaction ends. A right code records `emailProof.provedAtMs`, and on
 *   an `enroll` transaction the proof for its session alone, which a first
 *   binding in that session is then admitted on.
 */
import type { MfaTransaction } from "@o3co/auth-provider-core";
import { type MfaCeremonyCall, type MfaCeremonyKit, type MfaChallengeOutcome, type MfaVerifyOutcome } from "./ceremony.mjs";
/** The `factor_id` that names the proof, and the kind its code is digested and sealed under. */
export declare const ACCOUNT_EMAIL_FACTOR_ID = "account-email";
/** The account-email proof over the coordinator's `kit` (see this file's header). */
export declare function createAccountEmailProof(kit: MfaCeremonyKit): {
    /** The code mailed to `user`'s address: the login's `User` the transaction was opened for. */
    challenge(tx: MfaTransaction, user: Readonly<Record<string, unknown>> | undefined): Promise<MfaChallengeOutcome>;
    verify(call: MfaCeremonyCall & {
        readonly proof: unknown;
    }, tx: MfaTransaction): Promise<MfaVerifyOutcome>;
};
//# sourceMappingURL=proof.d.mts.map