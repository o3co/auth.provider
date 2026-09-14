import type { DPoPReplayStore } from "../replay-store.mjs";
interface MemoryReplayStoreOptions {
    /** Override the clock for tests. Default: `() => Date.now()`. */
    readonly now?: () => number;
}
export declare const createMemoryDPoPReplayStore: (options?: MemoryReplayStoreOptions) => DPoPReplayStore;
export {};
//# sourceMappingURL=replay-store.d.mts.map