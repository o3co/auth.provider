/**
 * Wrap a single ioredis connection into the 9 typed client wrappers
 * needed by `@o3co/auth-provider-redis` adapters. Production consumers
 * use this factory in their composition root and spread the result into
 * `bootstrapComponents`.
 *
 * Lives on the `@o3co/auth-provider-redis/ioredis` subpath so that consumers
 * importing the main entry (`@o3co/auth-provider-redis`) do NOT pull
 * `ioredis` types into their TypeScript dependency closure. The main entry
 * stays vendor-agnostic; only callers of `makeIoredisClients` need ioredis
 * installed. Future per-vendor wrappers (e.g. node-redis) will follow the
 * same `@o3co/auth-provider-redis/<vendor>` subpath convention.
 *
 * Per Copilot review on PR #102.
 *
 *     const io = new Redis(...);
 *     const clients = makeIoredisClients(io);
 *     await createApp({
 *         modules: [...],
 *         bootstrapComponents: { config, pathResolver, ...clients },
 *     });
 *
 * Mixed-backend deployments (e.g. memcached for ChallengeStore + redis
 * for FederationTokenStore) wire each slot individually instead of
 * spreading.
 *
 * Per Phase 10 addendum §3.
 */
export function makeIoredisClients(io) {
    const challengeStoreClient = {
        set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX"),
        pttl: (k) => io.pttl(k),
        del: (k) => io.del(k),
    };
    const replaySeenSetClient = {
        set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX"),
        exists: (k) => io.exists(k),
    };
    // RefreshTokenFamilyClient needs duplicate() returning DisposableRefreshTokenFamilyClient.
    // The duplicate is built by recursively wrapping the duplicated ioredis instance.
    const buildRefreshClient = (underlying) => ({
        set: (k, v, _mode, ttl, _cond) => underlying.set(k, v, "PX", ttl, "NX"),
        get: (k) => underlying.get(k),
        pttl: (k) => underlying.pttl(k),
        watch: (...keys) => underlying.watch(...keys),
        unwatch: () => underlying.unwatch(),
        multi: () => buildRefreshMulti(underlying.multi()),
        duplicate: () => {
            const dup = underlying.duplicate();
            const inner = buildRefreshClient(dup);
            const disposable = {
                ...inner,
                [Symbol.asyncDispose]: async () => {
                    await dup.quit();
                },
            };
            return disposable;
        },
    });
    const buildRefreshMulti = (p) => {
        const m = {
            set: (k, v, _mode, ttl) => {
                p.set(k, v, "PX", ttl);
                return m;
            },
            exec: async () => p.exec(),
        };
        return m;
    };
    const refreshTokenFamilyClient = buildRefreshClient(io);
    const userSessionStoreClient = {
        // Cast required because TypeScript cannot unify a single arrow function
        // against an overloaded property signature (the two `set` overloads
        // have distinct return types). The runtime branch on `cond` upholds
        // each overload's contract.
        set: ((k, v, _mode, ttl, cond) => cond === "NX"
            ? io.set(k, v, "PX", ttl, "NX")
            : io.set(k, v, "PX", ttl)),
        get: (k) => io.get(k),
        del: (k) => io.del(k),
    };
    const buildRPRegistryMulti = (p) => {
        const m = {
            hSet: (k, f, v) => {
                p.hset(k, f, v);
                return m;
            },
            pExpireAt: (k, ms) => {
                p.pexpireat(k, ms);
                return m;
            },
            exec: async () => p.exec(),
        };
        return m;
    };
    const sessionRPRegistryClient = {
        del: (k) => io.del(k),
        hSet: (k, f, v) => io.hset(k, f, v),
        hVals: (k) => io.hvals(k),
        multi: () => buildRPRegistryMulti(io.multi()),
        pExpireAt: (k, ms) => io.pexpireat(k, ms),
    };
    const buildSortedSetMulti = (p) => {
        const m = {
            pExpireAt: (k, ms) => {
                p.pexpireat(k, ms);
                return m;
            },
            zAdd: (k, e, opts) => {
                if (opts?.NX)
                    p.zadd(k, "NX", e.score, e.value);
                else
                    p.zadd(k, e.score, e.value);
                return m;
            },
            exec: async () => p.exec(),
        };
        return m;
    };
    const sortedSetClient = {
        del: (k) => io.del(k),
        multi: () => buildSortedSetMulti(io.multi()),
        pExpireAt: (k, ms) => io.pexpireat(k, ms),
        zAdd: (k, e, opts) => opts?.NX
            ? io.zadd(k, "NX", e.score, e.value)
            : io.zadd(k, e.score, e.value),
        zRange: (k, s, e) => io.zrange(k, s, e),
        zRem: (k, m) => io.zrem(k, m),
    };
    const federationTokenStoreClient = {
        get: (k) => io.get(k),
        // Cast required for overloaded `set`; see UserSessionStoreClient above.
        set: ((k, v, _mode, ttl, cond) => cond === "NX"
            ? io.set(k, v, "PX", ttl, "NX")
            : io.set(k, v, "PX", ttl)),
        del: (...keys) => io.del(...keys),
        scanIterator: ({ MATCH, COUNT }) => (async function* () {
            const stream = io.scanStream({ match: MATCH, count: COUNT });
            for await (const batch of stream) {
                for (const key of batch)
                    yield key;
            }
        })(),
    };
    const rateLimiterClient = {
        incr: (k) => io.incr(k),
        expire: (k, s) => io.expire(k, s),
    };
    return {
        challengeStoreClient,
        replaySeenSetClient,
        refreshTokenFamilyClient,
        userSessionStoreClient,
        sessionRPRegistryClient,
        sessionFamilyIndexClient: sortedSetClient,
        sessionFederationIndexClient: sortedSetClient,
        federationTokenStoreClient,
        rateLimiterClient,
    };
}
