/**
 * The one first-binding gate (the MFA ADR's D24, D25): whether a subject
 * holding no counting factor gives the account-email proof before it binds a
 * way into the account — a first factor at a login or from a session, a
 * first passkey, a first linked identity.
 *
 * Every input is handed in, so each caller decides in the same place over
 * what it can read: `mfa.enrollment.requireEmailProof`, whether a mail sender
 * is wired, the account's address as the session's enrollment facts say it
 * (core's one reading: `none`, `address` or `unreadable`), and D25's flag.
 *
 * - `never` asks for nothing, whatever the address; D25's flag asks whatever
 *   the setting; `always` asks always; `when-mail` asks when a sender is
 *   wired and the account has an address — or one it cannot read, which
 *   nobody can send the proof to.
 * - A proof asked for that nobody can give is `unprovable`, with why: the
 *   binding is refused, never let through without it.
 *
 * Whether a binding is a first one is read over the subject's records with
 * admission's presumption (`mayCount`): a record counts unless an installed
 * factor of its kind declares it does not. The same reading names the
 * binding a login reopens after a non-counting proof (`reopenedEnrollment`).
 */
import type { MailAddressFact, MfaFactor, MfaFactorRecord, MfaFactorResolver } from "@o3co/auth-provider-core";
export type { MailAddressFact };
/**
 * Whether `record` may hold a counting factor: unless an installed factor of
 * its kind declares it does not, so a kind no longer installed counts. Right
 * for admitting, for telling a first binding, and for clearing the witness
 * after a removal — it fails closed, a password never standing in for a
 * factor it cannot see; wrong for a last-factor check, which asks for a
 * record of an installed counting kind.
 */
export declare const mayCount: (factors: MfaFactorResolver, record: Pick<MfaFactorRecord, "kind">) => boolean;
/**
 * The enrollment a login reopens for once a non-counting proof left its
 * subject no counting factor it can use: `allowed`, a binding beside a
 * record that may count (one whose data does not open, a kind no longer
 * installed); else `required`, a first binding.
 */
export declare const reopenedEnrollment: (factors: MfaFactorResolver, records: readonly Pick<MfaFactorRecord, "kind">[]) => "allowed" | "required";
/**
 * How many records the subject holds once a recovery-code set issued beside
 * a binding by `binding` — `mfa` for a regeneration — stands beside
 * `records`: those records, less the sets the new one replaces, plus — the
 * recovery-code factor installed — the new set. Held to
 * `mfa.maxFactorsPerSubject`.
 */
export declare const recordsAfterRecoveryCodes: (factors: MfaFactorResolver, records: readonly Pick<MfaFactorRecord, "kind">[], binding: NonNullable<MfaFactorRecord["binding"]>) => number;
/**
 * How many records the subject holds once a first binding by `binding`
 * stands beside `records` (its own factor not among them): what its
 * recovery codes leave (`recordsAfterRecoveryCodes`), plus its factor. Held
 * to `mfa.maxFactorsPerSubject`.
 */
export declare const recordsAfterFirstBinding: (factors: MfaFactorResolver, records: readonly Pick<MfaFactorRecord, "kind">[], binding: NonNullable<MfaFactorRecord["binding"]>) => number;
/** A factor's `enrollable` that threw: its `kind`, and the factor's error as `cause`, never quoted. */
export declare class MfaEnrollableError extends Error {
    readonly kind: string;
    constructor(kind: string, cause: unknown);
}
/** The kinds of the installed counting factors, in registration order. */
export declare const countingKinds: (factors: MfaFactorResolver) => string[];
/**
 * Whether `user` may enroll `factor`, contributed as `kind`. A factor whose
 * `enrollable` throws cannot answer — an outage, never "not offered" — so
 * the throw goes through, as an {@link MfaEnrollableError} naming its kind.
 */
export declare const mayEnroll: (kind: string, factor: MfaFactor, user: Readonly<Record<string, unknown>>) => boolean;
/**
 * The counting factors `user` may enroll, in registration order: what a
 * first binding offers. A factor whose `enrollable` throws is an outage
 * ({@link mayEnroll}).
 */
export declare const enrollableKinds: (factors: MfaFactorResolver, user: Readonly<Record<string, unknown>>) => string[];
/** `mfa.enrollment.requireEmailProof`. */
export declare const REQUIRE_EMAIL_PROOF: readonly ["when-mail", "always", "never"];
/** One of {@link REQUIRE_EMAIL_PROOF}. */
export type RequireEmailProof = (typeof REQUIRE_EMAIL_PROOF)[number];
/** What the gate decides on. */
export interface FirstBindingGateInput {
    /** `mfa.enrollment.requireEmailProof`. */
    readonly requireEmailProof: RequireEmailProof;
    /** Whether a mail sender is wired. */
    readonly mailWired: boolean;
    /** The account's address as the session's enrollment facts say it (`SessionEnrollmentFacts.mailAddress`). */
    readonly mailAddress: MailAddressFact;
    /** D25's flag: an operator reset asked for the proof at the subject's next first binding. */
    readonly requiredAtNextBinding: boolean;
}
/** Why a proof asked for cannot be given: no sender, no address, or one no proof can be sent to. */
export type UnprovableReason = "no_sender" | "no_address" | "unreadable_address";
/**
 * `bind`: no proof is asked. `prove`: the account-email proof comes first,
 * and can be given. `unprovable`: a proof is asked that nobody can give.
 */
export type FirstBindingGate = {
    readonly outcome: "bind";
} | {
    readonly outcome: "prove";
} | {
    readonly outcome: "unprovable";
    readonly reason: UnprovableReason;
};
/** The gate over `input` (see this file's header). */
export declare function firstBindingGate(input: FirstBindingGateInput): FirstBindingGate;
//# sourceMappingURL=firstBinding.d.mts.map