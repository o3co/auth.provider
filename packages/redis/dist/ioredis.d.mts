import type { Redis } from "ioredis";
import type { ChallengeStoreClient, FederationTokenStoreClient, RateLimiterClient, RefreshTokenFamilyClient, ReplaySeenSetClient, SessionRPRegistryClient, SessionSidSortedSetClient, UserSessionStoreClient } from "./clients.mjs";
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
export declare function makeIoredisClients(io: Redis): {
    challengeStoreClient: ChallengeStoreClient;
    replaySeenSetClient: ReplaySeenSetClient;
    refreshTokenFamilyClient: RefreshTokenFamilyClient;
    userSessionStoreClient: UserSessionStoreClient;
    sessionRPRegistryClient: SessionRPRegistryClient;
    sessionFamilyIndexClient: SessionSidSortedSetClient;
    sessionFederationIndexClient: SessionSidSortedSetClient;
    federationTokenStoreClient: FederationTokenStoreClient;
    rateLimiterClient: RateLimiterClient;
};
//# sourceMappingURL=ioredis.d.mts.map