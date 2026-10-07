export const createMemoryDPoPReplayStore = (options = {}) => {
    const now = options.now ?? (() => Date.now());
    // key = `${jkt}:${jti}`, value = expiry epoch ms
    const seen = new Map();
    return {
        async seen(jti, jkt, ttlSeconds) {
            if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
                throw new RangeError(`DPoPReplayStore.seen: ttlSeconds must be a positive finite number (got ${String(ttlSeconds)})`);
            }
            const key = `${jkt}:${jti}`;
            const nowMs = now();
            const existing = seen.get(key);
            if (existing !== undefined && existing > nowMs) {
                return true;
            }
            seen.set(key, nowMs + ttlSeconds * 1000);
            // Opportunistic sweep — drop one expired key per call to amortize
            // cleanup. Real production deployments use Redis where TTL is
            // backend-native.
            for (const [k, expiry] of seen) {
                if (expiry <= nowMs) {
                    seen.delete(k);
                    break;
                }
            }
            return false;
        },
    };
};
