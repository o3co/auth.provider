import { type SessionLifecycleStore } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
/** What one case runs over. */
export interface SessionLifecycleStoreHarness {
    readonly store: SessionLifecycleStore;
    /**
     * The same backend through a second instance: another connection, pool or
     * client. Absent: `store` again, with no cross-process proof.
     */
    readonly second?: SessionLifecycleStore;
    /**
     * The store's clock, which the harness moves by hand. Absent: the store
     * reads a real clock, and the cases that need the time moved short of a
     * deadline are not run.
     */
    readonly clock?: {
        /** Epoch milliseconds, as the store reads them. */
        now(): number;
        advance(ms: number): void | Promise<void>;
    };
    /**
     * Moves the backend's clock past every retention deadline the store set
     * for the record of `sid`. It never judges what expires, and never
     * deletes.
     */
    readonly forceExpire?: (sid: string) => Promise<void>;
    /** A store over the same backend that cannot reach it. */
    readonly unreachable?: () => SessionLifecycleStore;
    readonly close?: () => Promise<void>;
}
export interface SessionLifecycleStoreContractInput {
    readonly build: () => Promise<SessionLifecycleStoreHarness>;
    /**
     * The hooks every harness `build` answers, declared up front, so the case
     * list is fixed when the suite is built. A declared hook that a harness
     * lacks fails its case; an undeclared one runs no case, and one passing
     * case names what was not run.
     */
    readonly supports?: {
        readonly clock?: boolean;
        readonly forceExpire?: boolean;
        readonly unreachable?: boolean;
    };
}
/** The cases of the `SessionLifecycleStore` contract over the harnesses `input` builds. */
export declare function sessionLifecycleStoreContract(input: SessionLifecycleStoreContractInput): readonly ContractCase[];
//# sourceMappingURL=sessionLifecycleStore.contract.d.mts.map