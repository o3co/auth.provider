/**
 * The `recovery_code` factor (the MFA ADR's D22, D25) and the set it issues.
 *
 * - It does not count, adds `recovery` and `mfa`, is not guessable, and is
 *   never enrolled on its own: a set is issued beside a first counting
 *   factor (`generateRecoveryCodes`), one record per set.
 * - A set is `count` long codes, answered once in groups; the record keeps
 *   only a keyed digest of each code, each naming its key, under the kind's
 *   digests — never a code — with the set's generation and whether its codes
 *   were answered (`shown`, false until then). A set written before either
 *   was kept reads as generation 0, shown.
 * - A verification reads the proof as typed and compares it with every
 *   digest of the set; a match answers the set without that digest, the rest
 *   of its data as it was, which the coordinator writes by compare-and-set,
 *   so a code is spent once. A digest whose key left the ring throws: an
 *   outage, never a code refused. A set with no code left is kept, and
 *   refuses every code.
 * - The one rule a set is held to before its verification
 *   (`recoverySetRefusal`): one below the subject's recovery-set floor is
 *   retired, and one whose digest needs a key the ring no longer holds names
 *   that key.
 */
import { type MfaDigests, type MfaFactor, type MfaFactorData } from "@o3co/auth-provider-core";
/** The kind a recovery-code set's record carries, and the key the factor is contributed under. */
export declare const RECOVERY_CODE_FACTOR_KIND = "recovery_code";
/** What the factor issues: how many codes a set holds. */
export interface RecoveryCodeFactorSettings {
    readonly count: number;
}
/** A set as issued: the codes to answer once, shown in groups, and the record's data, their digests. */
export interface RecoveryCodeSet {
    readonly codes: readonly string[];
    readonly data: MfaFactorData;
}
/** The `recovery_code` factor, issuing sets of `settings.count` codes. */
export declare function createRecoveryCodeFactor(settings: RecoveryCodeFactorSettings): MfaFactor;
/**
 * A new set of `generation` from `factor`, not yet shown, its codes digested
 * under `digests` (the kind's, under the ring's first key); `undefined` for a
 * factor this file did not make.
 */
export declare function generateRecoveryCodes(factor: MfaFactor, digests: MfaDigests, generation?: number): RecoveryCodeSet | undefined;
/** The generation of the set `data` holds, for a factor this file made; `undefined` otherwise, or for data that is not a set. */
export declare function recoverySetGeneration(factor: MfaFactor, data: MfaFactorData): number | undefined;
/** Whether the set `data` holds was answered, for a factor this file made; `undefined` otherwise, or for data that is not a set. */
export declare function recoverySetShown(factor: MfaFactor, data: MfaFactorData): boolean | undefined;
/** The set `data` holds, marked answered; `undefined` for data that is not a set. */
export declare function shownRecoverySet(data: MfaFactorData): MfaFactorData | undefined;
/** Whether the set `data` holds is below `floor`, the subject's recovery-set floor, for a factor this file made: retired. */
export declare function isRetiredRecoverySet(factor: MfaFactor, data: MfaFactorData, floor: number): boolean;
/** Why a verification is not handed a set: retired below the floor, or a digest under a key the ring lost. */
export type RecoverySetRefusal = {
    readonly reason: "retired";
} | {
    readonly reason: "key_unavailable";
    readonly keyId: string;
};
/**
 * Why the set `data` holds is not verified, for a factor this file made:
 * below `floor`, the subject's recovery-set floor, it is retired; a digest
 * whose key `holdsKey` denies names that key. `undefined` for anything else —
 * another factor, a set the rule passes, or data that is not a set, which
 * the verification answers.
 */
export declare function recoverySetRefusal(factor: MfaFactor, data: MfaFactorData, context: {
    readonly floor: number;
    readonly holdsKey: (keyId: string) => boolean;
}): RecoverySetRefusal | undefined;
/** Whether `factor` is one this file made: a recovery-code factor whose sets this file reads. */
export declare const isRecoveryCodeFactor: (factor: MfaFactor) => boolean;
/** The key ids the set `data`'s digests name, for a factor this file made; `undefined` otherwise, or for data that is not a set. */
export declare function recoverySetKeyIds(factor: MfaFactor, data: MfaFactorData): string[] | undefined;
/** Whether `data` is a set with no code left, for a factor this file made; data that is not a set is not one. */
export declare function isExhaustedRecoverySet(factor: MfaFactor, data: MfaFactorData): boolean;
/**
 * How many codes the set `data` holds, for a factor this file made; none
 * for data that is not a set; `undefined` for any other factor.
 */
export declare function recoveryCodesLeft(factor: MfaFactor, data: MfaFactorData): number | undefined;
//# sourceMappingURL=factor.d.mts.map