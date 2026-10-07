import { type Logger, type MfaDigests, type MfaFactorData, type MfaFactorState, type SealingKeyRing } from "@o3co/auth-provider-core";
/** The purpose a factor's data is sealed under. Fixed while any is at rest. */
export declare const MFA_FACTOR_SEALING_PURPOSE = "o3co:mfa:factor";
/** The purpose a pending challenge's state is sealed under. */
export declare const MFA_CHALLENGE_SEALING_PURPOSE = "o3co:mfa:challenge";
/** The purpose a pending enrollment's state is sealed under. */
export declare const MFA_ENROLLMENT_SEALING_PURPOSE = "o3co:mfa:enrollment";
/** The record a factor's data belongs to: what its sealing is bound to. */
export interface MfaFactorBinding {
    readonly subject: string;
    readonly id: string;
    readonly kind: string;
}
/** The ceremony a state belongs to: its transaction, the factor's kind, and whether it is a challenge's or a pending enrollment's. */
export interface MfaStateBinding {
    readonly transactionId: string;
    readonly kind: string;
    readonly use: "challenge" | "enrollment";
}
/**
 * What opening found: the value and the key that sealed it; `unreadable` —
 * not this envelope, or not for this binding; or `key_unavailable` — sealed
 * under a key no longer in the ring, named so it can be put back.
 */
export type OpenedMfaValue<T> = {
    readonly state: "ok";
    readonly value: T;
    readonly keyId: string;
} | {
    readonly state: "unreadable";
} | {
    readonly state: "key_unavailable";
    readonly keyId: string;
};
/** Sealing, opening and digesting under one key ring. */
export interface MfaSealing {
    /** `data`'s copy ({@link copyFactorValue}) as JSON, sealed to its record under the first key. A `RangeError` for data that is not a plain JSON object of plain JSON values, or a record with an empty part. */
    sealFactorData(binding: MfaFactorBinding, data: MfaFactorData): string;
    /** The data sealed to this record; never throws. */
    openFactorData(binding: MfaFactorBinding, sealed: unknown): OpenedMfaValue<MfaFactorData>;
    /** `state`'s copy ({@link copyFactorValue}) as JSON, sealed to its ceremony under the first key. */
    sealState(binding: MfaStateBinding, state: MfaFactorState): string;
    /** The state sealed to this ceremony; never throws. */
    openState(binding: MfaStateBinding, sealed: unknown): OpenedMfaValue<MfaFactorState>;
    /** Keyed digests bound to `kind`, as a factor of that kind is handed them. */
    digestsFor(kind: string): MfaDigests;
    /** Whether the ring holds the key `keyId` names: a digest made under another cannot be compared. */
    holdsKey(keyId: string): boolean;
}
export interface MfaSealingOptions {
    /** The ring, in order: the first key seals and digests, every key opens and matches. */
    readonly ring: SealingKeyRing;
    /** Where `mfa_factor_sealed_with_retired_key` goes. Absent, core's `consoleLogger`. */
    readonly logger?: Logger;
}
/**
 * A factor's data, state or response as its plain JSON copy (core's
 * `copyPlainJson`): each field read once, frozen at every depth, what is
 * sealed or answered, and what the coordinator hands everything that acts on
 * the value, so nothing acts on what was not taken. It must be an object, not
 * a list. Anything else is a `RangeError` with one fixed text that quotes
 * nothing of the value, so a value is sealed whole or not at all, never in part.
 *
 * Not core's `copyByName` (beside `readPlainFields`), which snapshots a
 * record by the fields its type declares and so takes a record of any shape:
 * a factor's data and state declare no fields, so nothing names what to read
 * from a class's instance, and only a value JSON writes whole is taken.
 */
export declare function copyFactorValue(value: unknown): Readonly<Record<string, unknown>>;
/** A sealing over `ring`. A `RangeError` for a ring the envelope refuses, or an empty one. */
export declare function createMfaSealing({ ring, logger }: MfaSealingOptions): MfaSealing;
//# sourceMappingURL=sealing.d.mts.map