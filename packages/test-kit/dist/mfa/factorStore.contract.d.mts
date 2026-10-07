import { type MfaFactorStore } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
/** What one case runs over: a fresh, empty store, and what else the backend gives. */
export interface MfaFactorStoreHarness {
    /** The store under test, holding nothing. */
    readonly store: MfaFactorStore;
    /**
     * The same backend through a second instance: another connection, pool or
     * adapter. Absent: `store` again, which is right for an in-process store
     * and gives no cross-process proof.
     */
    readonly second?: MfaFactorStore;
    /** A store over the same backend that cannot reach it. Needs `supports.unreachable`. */
    readonly unreachable?: () => MfaFactorStore;
    /**
     * Moves the backend's clock past any retention deadline the store set
     * (`subject` names the set the case expires). It never judges membership,
     * and never deletes: that an emptied set's tombstone expires and a set
     * holding a record does not is the store's own doing. Needs
     * `supports.forceExpire`; only the factor set's binding uses it.
     */
    readonly forceExpire?: (subject: string) => Promise<void>;
    /** Releases what the store runs on once the case ends. */
    readonly close?: () => Promise<void>;
}
export interface MfaFactorStoreContractInput {
    /** Builds a fresh harness for each case. */
    readonly build: () => Promise<MfaFactorStoreHarness>;
    /**
     * The hooks every harness `build` answers, declared up front so the case
     * list is fixed when the suite is built. A declared hook a harness lacks
     * fails its case; an undeclared one runs no case, and one passing case
     * names what did not run.
     */
    readonly supports?: {
        readonly unreachable?: boolean;
        readonly forceExpire?: boolean;
    };
}
/** One passing case that names what did not run, or none when everything ran. */
export declare function notRunCase(left: readonly string[]): ContractCase[];
/** `harness.unreachable`, bound to the harness, or the case's failure when a harness that declared it lacks it. */
export declare function unreachableOf(harness: MfaFactorStoreHarness): () => MfaFactorStore;
/** Whether `run` rejects; `what` names it in the failure. */
export declare function rejects(run: () => Promise<unknown>, what: string): Promise<void>;
/** The cases of the factor store's contract over the harnesses `input` builds. */
export declare function mfaFactorStoreContract(input: MfaFactorStoreContractInput): readonly ContractCase[];
//# sourceMappingURL=factorStore.contract.d.mts.map