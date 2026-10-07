import { type MfaFactorResolver, type MfaSubjectRecoveryOperation, type MfaTransactionStore, type SubjectRevocation } from "@o3co/auth-provider-core";
import type { MfaFactorSet } from "./factorSet.mjs";
/** What minting an authorization came to. */
export type MfaRecoveryMint = {
    readonly outcome: "minted";
}
/** The factor verified is guessable, or not installed: it authorizes nothing. */
 | {
    readonly outcome: "not_exempt";
} | {
    readonly outcome: "unavailable";
    readonly cause: unknown;
};
/** What the store gave back, as an applied recovery reports it. */
export interface MfaRecoveryCleared {
    readonly week: boolean;
    readonly run: boolean;
    readonly hard: boolean;
}
/** Whether a release applied its authorization now, with what it gave back, or found it applied before, applying nothing more. */
type Applied = {
    readonly applied: true;
    readonly cleared: MfaRecoveryCleared;
} | {
    readonly applied: false;
};
/** What a release came to. */
export type MfaLockRelease = ({
    readonly outcome: "released";
    readonly generation: number;
} & Applied)
/** The hard hold stands, until every guessable factor is bound again: never read as released. */
 | ({
    readonly outcome: "held";
    readonly hold: "hard";
    readonly generation: number;
    /** From when a rebind counts: a guessable factor created after it is a rebind, one created at or before it is not. */
    readonly rebindAfter: Date;
} & Applied) | {
    readonly outcome: "refused";
    readonly reason: "not_revoked_since" | "no_revocation_boundary";
    /** From when a rebind counts while the hard hold stands, as `held` says it; `null` when it does not. */
    readonly rebindAfter: Date | null;
} | {
    readonly outcome: "refused";
    readonly reason: "exempt_proof_required";
} | {
    readonly outcome: "busy";
    readonly retryAfterSeconds: number;
} | {
    readonly outcome: "unavailable";
    readonly store: "mfa_factor" | "mfa_transaction" | "subject_revocation";
    readonly step: string;
    readonly cause: unknown;
};
export interface MfaLockRecovery {
    /** An authorization for `sid` minted when a factor of `kind` verified at `nowMs`; nothing for a guessable one. Never throws. */
    authorize(subject: string, sid: string, kind: string, nowMs: number): Promise<MfaRecoveryMint>;
    /** The subject's lock released on the authorization minted in `sid`. Never throws. */
    release(subject: string, sid: string): Promise<MfaLockRelease>;
}
export interface MfaLockRecoveryOptions {
    readonly store: Pick<MfaTransactionStore, "authorizeSubjectRecovery">;
    /** Where the release is applied under the subject's lease. */
    readonly factorSet: Pick<MfaFactorSet, "recover">;
    readonly factors: MfaFactorResolver;
    /** The subjects' sessions boundary; none wired, a release has none to hand. */
    readonly subjectRevocation?: Pick<SubjectRevocation, "revokedBefore">;
    /** `mfa.manage.maxAgeSeconds`, in milliseconds: how long an authorization lasts. */
    readonly manageMaxAgeMs: number;
    /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
    readonly now?: () => number;
}
/**
 * Records in `store` a one-time authorization of `operation` for `subject`
 * — in session `sid` for a recover, none for a reset — under a fresh 16-byte
 * recovery id, ending `lifetimeMs` after `nowMs`. Throws what the store throws.
 */
export declare function mintSubjectRecovery(store: Pick<MfaTransactionStore, "authorizeSubjectRecovery">, subject: string, authorization: {
    readonly operation: MfaSubjectRecoveryOperation;
    readonly sid: string | undefined;
    readonly nowMs: number;
    readonly lifetimeMs: number;
}): Promise<void>;
/** The authorized-recovery entry over `options` (see this file's header). */
export declare function createMfaLockRecovery(options: MfaLockRecoveryOptions): MfaLockRecovery;
export {};
//# sourceMappingURL=lockRecovery.d.mts.map