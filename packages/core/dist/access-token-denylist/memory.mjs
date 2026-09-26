/**
 * In-process Map-backed AccessTokenDenylist.
 *
 * GC is lazy (per-operation cleanup of expired entries on `has`). No background
 * sweep. Idempotent `add`: a second call for the same jti overwrites the
 * expiry timestamp.
 */
export function createMemoryAccessTokenDenylist() {
    const entries = new Map();
    return {
        kind: "memory",
        async add(jti, expiresAtMs) {
            entries.set(jti, expiresAtMs);
        },
        async has(jti) {
            const expiresAtMs = entries.get(jti);
            if (expiresAtMs === undefined)
                return false;
            if (expiresAtMs <= Date.now()) {
                entries.delete(jti);
                return false;
            }
            return true;
        },
    };
}
