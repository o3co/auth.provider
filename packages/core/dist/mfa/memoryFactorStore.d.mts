import type { MfaFactorStore } from "./factorStore.mjs";
export interface MemoryMfaFactorStoreOptions {
    /** The clock a tombstone expires by, in epoch milliseconds. Default `Date.now`. */
    readonly now?: () => number;
}
export declare function createMemoryMfaFactorStore(options?: MemoryMfaFactorStoreOptions): MfaFactorStore;
//# sourceMappingURL=memoryFactorStore.d.mts.map