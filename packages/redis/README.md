# @o3co/auth-provider-redis

Redis-backed adapters and `defineModule` manifests for `@o3co/auth-provider-core`.

Phase 5 (v0.5.0) ships `ChallengeStore` and `ReplaySeenSet` adapters. Consumers
provide a structural `RedisClient` (any library — ioredis, node-redis — that
exposes the small operation surface in `src/types.mts`).
