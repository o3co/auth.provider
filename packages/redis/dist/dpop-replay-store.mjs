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
export const createRedisDPoPReplayStore = (options) => {
    const prefix = options.keyPrefix ?? "dpop:replay:";
    return {
        async seen(jti, jkt, ttlSeconds) {
            // Mirror the memory adapter's RangeError guard so the
            // `DPoPReplayStore.seen` interface contract holds uniformly across
            // shipped adapters (replay-store.mts JSDoc: implementations SHOULD
            // throw on non-positive / non-finite ttlSeconds).
            if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
                throw new RangeError(`DPoPReplayStore.seen: ttlSeconds must be a positive finite number (got ${String(ttlSeconds)})`);
            }
            const key = `${prefix}${jkt}:${jti}`;
            // SET key value NX PX ttlMillis — atomic check-and-set
            const result = await options.client.set(key, "1", "PX", ttlSeconds * 1000, "NX");
            // result === "OK" → set succeeded → was NOT seen before
            // result === null → key already existed → IS a replay
            return result === null;
        },
    };
};
