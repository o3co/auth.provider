import { type MfaFactorRecord, type MfaFactorResolver, type MfaFactorStore } from "@o3co/auth-provider-core";
import type { MfaFactorSetWrites } from "../factorSet.mjs";
import type { MfaSealing } from "../sealing.mjs";
/** Why the sets that stood were kept on purpose: the binding, by a sign-in alone, they were kept for. */
export interface MfaKeptRecoveryCodes {
    readonly kept: "password_binding" | "federated_binding";
}
/** Why a set that stood may still be stored beside the new one: kept for a binding by a sign-in alone, or retired and not removed. */
export type MfaUnreplacedRecoveryCodes = MfaKeptRecoveryCodes | {
    readonly cause: unknown;
};
/**
 * What issuing came to: nothing while the factor is off, or not issued, with
 * why — `conflict` when the subject's factor set changed before the new set
 * was written; or the codes to answer once, whether the new set replaces one
 * — `regenerated`: one stood — and why one may still be stored
 * (`unreplaced`).
 */
export type MfaIssuedRecoveryCodes = {
    readonly issued: true;
    readonly codes: readonly string[];
    readonly regenerated: boolean;
    readonly unreplaced?: MfaUnreplacedRecoveryCodes;
} | {
    readonly issued: false;
    readonly cause: unknown;
    readonly conflict?: true;
} | undefined;
/** A set written and not yet shown: its codes are reached through `show` alone, which marks it shown (see this file's header). Never throws. */
export interface MfaUnshownRecoveryCodes {
    readonly written: "unshown";
    show(): Promise<Exclude<MfaIssuedRecoveryCodes, undefined>>;
}
/** What writing a set came to: nothing while the factor is off, not issued with why, or the set written unshown. */
export type MfaWrittenRecoveryCodes = MfaUnshownRecoveryCodes | Extract<MfaIssuedRecoveryCodes, {
    readonly issued: false;
}> | undefined;
export interface IssueRecoveryCodesOptions {
    readonly factors: MfaFactorResolver;
    /** The subject's factor set and recovery-set floor, as the subject's lease hands them. */
    readonly writes: Pick<MfaFactorSetWrites, "factors" | "recoverySetFloor">;
    readonly sealing: MfaSealing;
    readonly subject: string;
    /** What authorized the binding the set is issued beside: `mfa` for a regeneration. */
    readonly binding: NonNullable<MfaFactorRecord["binding"]>;
    readonly nowMs: number;
}
export interface WriteRecoveryCodesOptions extends IssueRecoveryCodesOptions {
    /** The factor store `show` marks the set shown through, once the lease that wrote it is released. */
    readonly markedThrough: Pick<MfaFactorStore, "update">;
}
/** Whether a set issued beside a binding by `binding` replaces the sets that stood: the one rule (see this file's header). */
export declare const replacesStandingSets: (binding: NonNullable<MfaFactorRecord["binding"]>) => boolean;
/** A new set for `options.subject`, marked shown at once through the writes it is handed (see this file's header). */
export declare function issueRecoveryCodes(options: IssueRecoveryCodesOptions): Promise<MfaIssuedRecoveryCodes>;
/** A new set for `options.subject`, written unshown for its answer to mark (see this file's header). */
export declare function writeRecoveryCodes(options: WriteRecoveryCodesOptions): Promise<MfaWrittenRecoveryCodes>;
//# sourceMappingURL=issue.d.mts.map