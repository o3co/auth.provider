# @o3co/auth-provider-redis

Redis-backed adapters and `defineModule` manifests for `@o3co/auth-provider-core`.

## Requirements

- **Node.js** `>=22.0.0`
- **Redis server** `>=7.2 LTS` — the session adapters issue a
  `PEXPIREAT … NX` + `PEXPIREAT … GT` pair for safe concurrent TTL writes
  (D-10). NX sets the TTL on first write because a bare `… GT` silently
  no-ops on a key with no existing TTL; GT then prevents truncation under
  stale-`expiresAt` concurrent writes. Both flags require Redis 7.0+; we
  pin to 7.2 LTS. Redis 6.x is not supported. Tested against:
  - AWS ElastiCache for Redis 7.2
  - Upstash Redis (7.2 compatible)
  - Redis Cloud 7.2
  - Self-managed `redis:7.2-alpine`
- **Redis Lua scripting** (`EVAL` / `EVALSHA`) — the federation-token
  advisory lock release path is implemented via an atomic Lua compare-and-
  delete script (D-9, closes CR-1 / OR-13 / SF-4). Lua is enabled by default
  on Redis standalone and Sentinel mode. **Redis Cluster mode with Lua
  scripting disabled is not supported by the bundled `makeIoredisClients()`
  adapter** — operators on AWS ElastiCache for Redis Cluster mode must
  either enable Lua scripting in their cluster configuration, or wire a
  custom `FederationTokenStoreClient` whose `compareAndDelete` uses an
  alternative atomic primitive (e.g., a Cluster-safe transaction).

This package ships nine adapters covering every redis-backed component that
`@o3co/auth-provider-core` exposes as a typed slot:

- `ChallengeStore` (challenges)
- `ReplaySeenSet` (replay-seen-set)
- `RefreshTokenFamilyStore` / `RefreshTokenFamilyRotation` /
  `RefreshTokenFamilyRevocation` (refresh-token-family)
- `UserSessionStore`, `SessionRPRegistry`, `SessionFamilyIndex`,
  `SessionFederationIndex` (user sessions, A4 four-store split)
- `FederationTokenStore` (federation tokens)
- `RateLimiter` (rate-limiter)
- `CodeRepository` (relocated from `@o3co/auth-provider-foundation` in
  v0.5.0; `redisCodeRepositoryBuilder` for AdapterFactory wiring)

## Backing-client contract

Each adapter consumes a **per-purpose backing-client interface** declared
in `@o3co/auth-provider-core` (e.g. `ChallengeStoreClient`,
`FederationTokenStoreClient`, `RateLimiterClient`). The interfaces declare
only the methods the adapter actually calls — `ChallengeStoreClient` is
`{ set(NX); pttl; del }`, `RateLimiterClient` is `{ incr; expire }`, etc.
Consumers wire whichever backend wrapper (ioredis, node-redis, custom
shim, future memcached/postgres adapters) satisfies the per-purpose
interface.

For the common case of one ioredis connection serving every redis-backed
adapter, this package exports `makeIoredisClients(io)`:

```ts
import { Redis } from "ioredis";
import { createApp } from "@o3co/auth-provider-core";
import { makeIoredisClients, redisChallengeStoreModule } from "@o3co/auth-provider-redis";

const io = new Redis({ host: "localhost", port: 6379 });
const clients = makeIoredisClients(io);

const handle = await createApp({
    modules: [redisChallengeStoreModule /* + others */],
    bootstrapComponents: { config, pathResolver, ...clients },
});
```

For mixed-backend deployments (e.g. memcached for `ChallengeStore` +
redis for `FederationTokenStore`), wire each per-purpose slot
individually instead of spreading.

## Module pattern vs AdapterFactory pattern

Each redis adapter ships in two flavours:

- A **`defineModule` manifest** (`redisChallengeStoreModule`,
  `redisFederationTokenStoreModule`, etc.) for declarative wiring via
  `createApp({ modules: [...] })`.
- An **`AdapterBuilder`** (`redisChallengeStoreBuilder`,
  `redisCodeRepositoryBuilder`, etc.) for runtime-config-driven wiring
  via `factory.register("redis", redisXxxBuilder)` + `factory.create({
  type: "redis", ... })`.

The Module pattern is canonical for v0.5.0+; the AdapterFactory pattern
remains supported for HOCON-config-driven backend selection in the
standalone template and similar deployments.

## Internal helpers

`src/internal/lock.mts` (`createRedisLock`) and `src/internal/crypto.mts`
(AES-256-GCM token-field crypto helpers) are private to this package.
The lock embeds federation-tokens-specific options (`{ sid,
federationName }`) in `AcquireLockOptions` and is not currently
backend-agnostic; a public generic-lock API is on the roadmap for
v0.6+.
