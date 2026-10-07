import { type FederationTokenStore } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
/** What one case runs over. */
export interface FederationTokenStoreConditionalHarness {
    readonly store: FederationTokenStore;
    /**
     * The same backend through a second instance: another connection, pool or
     * client. Absent: `store` again, with no cross-process proof.
     */
    readonly second?: FederationTokenStore;
    /**
     * Moves the backend's clock past the retention deadline the store set for
     * the record of `(sid, federationName)`. It never judges what expires, and
     * never deletes.
     */
    readonly forceExpire?: (sid: string, federationName: string) => Promise<void>;
    /** A store over the same backend that cannot reach it. */
    readonly unreachable?: () => FederationTokenStore;
    readonly close?: () => Promise<void>;
}
export interface FederationTokenStoreConditionalContractInput {
    readonly build: () => Promise<FederationTokenStoreConditionalHarness>;
    /**
     * The hooks every harness `build` answers, declared up front, so the case
     * list is fixed when the suite is built. A declared hook that a harness
     * lacks fails its case; an undeclared one runs no case, and one passing
     * case names what was not run.
     */
    readonly supports?: {
        readonly forceExpire?: boolean;
        readonly unreachable?: boolean;
    };
}
/** The cases of `FederationTokenStore`'s conditional writes over the harnesses `input` builds. */
export declare function federationTokenStoreConditionalContract(input: FederationTokenStoreConditionalContractInput): readonly ContractCase[];
//# sourceMappingURL=federationTokenStoreConditional.contract.d.mts.map