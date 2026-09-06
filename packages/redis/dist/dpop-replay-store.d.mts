import type { DPoPReplayStore } from "@o3co/auth-provider-dpop";
/**
 * Minimal backing client for the DPoP replay store.
 * Separate from the general `ReplaySeenSetClient` because the DPoP store
 * needs only the atomic SET NX PX operation — no `exists` query, no
 * challenge lifecycle ops.
 */
export interface DPoPReplayStoreClient {
    set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
}
export interface RedisDPoPReplayStoreOptions {
    readonly client: DPoPReplayStoreClient;
    readonly keyPrefix?: string;
}
/**
 * Redis-backed DPoPReplayStore. Uses `SET key 1 NX PX ttlMs` for atomic
 * check-and-mark — a single round-trip with no TOCTOU window.
 *
 *   result === "OK"   → key was SET (not previously seen) → return false
 *   result === null   → key already existed (replay)      → return true
 *
 * Per Wave 2 Phase 2 spec §5.5 and design principle §3.3 (atomicity).
 * Required for multi-process / clustered deployments where the in-memory
 * adapter cannot share state across processes.
 */
export declare const createRedisDPoPReplayStore: (options: RedisDPoPReplayStoreOptions) => DPoPReplayStore;
//# sourceMappingURL=dpop-replay-store.d.mts.map