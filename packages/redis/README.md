# @o3co/auth-provider-redis

Redis-backed adapters and `defineModule` manifests for `@o3co/auth-provider-core`.

This package ships nine adapters covering every redis-backed component that
`@o3co/auth-provider-core` exposes as a typed slot:

- `ChallengeStore` (challenges)
- `ReplaySeenSet` (replay-seen-set)
- `RefreshTokenFamilyStore` / `RefreshTokenRotation` /
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
