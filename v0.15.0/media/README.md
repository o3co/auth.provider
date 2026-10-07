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

This package ships sixteen adapters covering every redis-backed component
that `@o3co/auth-provider-core` exposes as a typed slot:

- `ChallengeStore` (challenges)
- `ReplaySeenSet` (replay-seen-set)
- `AccessTokenDenylist` (access-token-denylist) — the store behind RFC 7009
  access-token revocation. The in-process alternative forks per replica, so a
  token revoked on one replica keeps working on the others; core refuses that
  one under `deployment.mode = "multi"` (#277)
- `RefreshTokenFamilyStore` / `RefreshTokenFamilyRotation` /
  `RefreshTokenFamilyRevocation` (refresh-token-family)
- `UserSessionStore`, `SessionRPRegistry`, `SessionFamilyIndex`,
  `SessionFederationIndex` (user sessions, A4 four-store split)
- `SubjectSessionIndex` / `SubjectRevocation` (subject-level revocation,
  #321) — bundled with the four above in `redisSessionStoresModule`
- `FederationTokenStore` (federation tokens)
- `FederationGrantStore` (federation grants, #593) — offline delegation of an
  upstream's tokens to a backend or an agent, with no session behind the call.
  `createRedisFederationGrantStore` takes its own connection through
  `makeIoredisFederationGrantStoreClient`, and no module factory yet: the
  routes and the configuration arrive with the package's slice.
- `RateLimiter` (rate-limiter)
- `CodeRepository` (relocated from `@o3co/auth-provider-foundation` in
  v0.5.0; `redisCodeRepositoryBuilder` for AdapterFactory wiring)
- `DeviceCodeStore` (device-code-store) — pending RFC 8628 device
  authorizations for `@o3co/auth-provider-device-grant`. The in-process
  alternative forks per replica — the human approves on the replica that
  served the verification page while the device polls one that has never
  heard of the code — so core refuses it under `deployment.mode = "multi"`;
  this adapter is what lets the grant run scaled (#433). See "Device
  authorizations share one slot" below before choosing it.
- `ConsentStore` / `PendingConsentStore` (consent-store) — the consent step
  for clients that are not first-party: what a user agreed a client may
  obtain, and the `/authorize` request parked while the consent page asks.
  Core's in-process pair forks per replica and is refused under
  `deployment.mode = "multi"`; `redisConsentStoreModule` provides both slots
  (#561). See "Consent records and parked requests" below.

## Backing-client contract

Each adapter consumes a **per-purpose backing-client interface** declared
in this package (`src/clients.mts` — e.g. `ChallengeStoreClient`,
`FederationTokenStoreClient`, `RateLimiterClient`). Core deliberately does
not declare them: the backing-client vocabulary belongs to the adapter
package (v0.5.0 pre-tag interface review S3). The interfaces declare
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
import { redisChallengeStoreModule } from "@o3co/auth-provider-redis";
import { makeIoredisClients } from "@o3co/auth-provider-redis/ioredis";

const io = new Redis({
    host: "localhost",
    port: 6379,
    // Required in production. On the driver's defaults there is no command
    // timeout at all, so a partition does not produce errors — it produces
    // waiting, and requests pile up behind a socket that will not answer. See
    // "Failure timing" below.
    commandTimeout: 1_000,
    connectTimeout: 5_000,
    maxRetriesPerRequest: 3,
});

// Required. ioredis emits `error` on socket failures — including while it is
// auto-reconnecting — and an EventEmitter `error` with no listener throws and
// takes the process down. This connection is yours: `makeIoredisClients` does
// not attach a listener to it, only to the connections it opens itself for
// refresh rotation.
io.on("error", (err) => logger.error({ err }, "redis_client_error"));
const clients = makeIoredisClients(io);

const handle = await createApp({
    modules: [redisChallengeStoreModule /* + others */],
    bootstrapComponents: { config, pathResolver, ...clients },
});
```

For mixed-backend deployments (e.g. memcached for `ChallengeStore` +
redis for `FederationTokenStore`), wire each per-purpose slot
individually instead of spreading.

### Failure timing

`makeIoredisClients` derives every client from the one connection you hand it
and opens none of its own (the exception is
`refreshTokenFamilyClient.duplicate()`, one per refresh rotation).
Connection-level ioredis options are
therefore shared by all sixteen purposes, and the ones governing how a partition
*ends* are the ones worth setting deliberately:

- **`commandTimeout`** is the only option that bounds a command which never
  reaches the wire. ioredis arms it before deciding whether the socket is
  writable, so it covers the offline queue too — and it is the sole guard
  against a zombie connection where no `close` event fires and the reconnect
  path is never entered. Without it, a rate limiter running fail-closed never
  gets an error to fail on, so it never sheds load (#286).
- **`maxRetriesPerRequest`** bounds how *deep* the offline queue gets: it fails
  the whole queue once the reconnect count is reached. The default is 20, which
  on ioredis 6's exponential backoff is tens of seconds of accumulation.
- **`enableOfflineQueue: false`** makes a command issued while the socket is
  down reject immediately rather than after `commandTimeout`. It is the right
  answer for a rate-limiter connection and the wrong one for a session or
  refresh-token connection, where it turns a sub-second reconnect blip into a
  forced re-login. Because it is per-connection, choosing it for one purpose
  means giving that purpose its own `Redis` instance — the per-purpose client
  interfaces exist for exactly that, and a second socket should be a deliberate
  choice rather than a side effect.

## Module pattern vs AdapterFactory pattern

Each redis adapter ships in two flavours:

- A **`defineModule` manifest** (`redisChallengeStoreModule`,
  `redisFederationTokenStoreModule`, etc.) for declarative wiring via
  `createApp({ modules: [...] })`. The federation-token store also has
  `redisFederationTokenStoreModuleFor({ environment })` for a composition root
  that selects its config by a name other than `NODE_ENV` (the standalone's
  `CONFIG_ENV`): its `allow-plaintext` guard reads that name in addition to
  `NODE_ENV`, and `deployment.mode` off the config — `"multi"` refuses
  plaintext in every environment (#473).
- An **`AdapterBuilder`** (`redisChallengeStoreBuilder`,
  `redisCodeRepositoryBuilder`, etc.) for runtime-config-driven wiring
  via `factory.register("redis", redisXxxBuilder)` + `factory.create({
  type: "redis", ... })`.

| Module | Requires | Provides | Config key | Builder |
| --- | --- | --- | --- | --- |
| `redisChallengeStoreModule` | `challengeStoreClient` | `challengeStore` | `redisChallengeStore` | `redisChallengeStoreBuilder` |
| `redisReplaySeenSetModule` | `replaySeenSetClient` | `replaySeenSet` | `redisReplaySeenSet` | `redisReplaySeenSetBuilder` |
| `redisAccessTokenDenylistModule` | `accessTokenDenylistClient` | `accessTokenDenylist` | `redisAccessTokenDenylist` | `redisAccessTokenDenylistBuilder` |
| `redisRefreshTokenFamilyStoreModule` | `refreshTokenFamilyClient` | `refreshTokenFamilyStore` | `redisRefreshTokenFamilyStore` | `redisRefreshTokenFamilyStoreBuilder` |
| `redisSessionStoresModule` | the six session/subject clients | the six session/subject stores | `redisSessionStores` | per-store builders |
| `redisFederationTokenStoreModule` | `federationTokenStoreClient` | `federationTokenStore` | `redisFederationTokenStore` | `redisFederationTokenStoreBuilder` |
| `redisRateLimiterModule` | `rateLimiterClient` | `rateLimiter` | `redisRateLimiter` | `redisRateLimiterBuilder` |
| `redisCodeRepositoryModule` | `codeRepositoryClient` | `codeRepository` | `redisCodeRepository` | `redisCodeRepositoryBuilder` |
| `redisDeviceCodeStoreModule` | `deviceCodeStoreClient` | `deviceCodeStore` | `redisDeviceCodeStore` | `redisDeviceCodeStoreBuilder` |
| `redisConsentStoreModule` | `consentStoreClient`, `pendingConsentStoreClient` | `consentStore`, `pendingConsentStore` | `redisConsentStore` | `redisConsentStoreBuilder`, `redisPendingConsentStoreBuilder` |

Every module also requires `config`. The `*Client` column is the slot
`makeIoredisClients` fills; a composition that wires a Redis-branch module
without providing its client slot fails stage-1 boot with
`missing-required-component` — named at boot, not at the first command.

The Module pattern is canonical for v0.5.0+; the AdapterFactory pattern
remains supported for HOCON-config-driven backend selection in the
standalone template and similar deployments.

## Logout keys, and the keyspace scan you still have to turn off

**Read this before assuming logout stopped scanning: out of the box, it has
not.** `scanFallback` ships enabled, so every `FederationTokenStore.removeBySid`
still performs one `SCAN` of the whole keyspace. The O(session) behaviour
arrives when you set it to `false` — see below for when that is safe.

Every store a logout touches is keyed by `sid`, so the *removal* is already a
handful of named keys rather than a search:

| Key | Type | Holds |
| --- | --- | --- |
| `${keyPrefix}${sid}:${federationName}` | string | one federation token envelope |
| `${keyPrefix}idx:${sid}` | **set** | the federation names attached to `${sid}` |
| `${keyPrefix}lock:${sid}:${federationName}` | string | the advisory lock |

### Federation grants (#593)

Its own keyspace, and its own connection, because what it holds outlives every
session: default prefix `fg:`.

| Key | Type | Holds |
| --- | --- | --- |
| `fg:{<id>}:grant` | **hash** | the non-secret record: status, version, the authorization as one canonical text, the current intent |
| `fg:{<id>}:cred` | string | one sealed credential (`v2.<key id>.<iv>.<ciphertext>.<tag>`) |
| `fg:{<id>}:lock` | string | the lock one refresh holds |
| `fg:sub:<subject>` | **zset** | that subject's grants, scored by the instant each stops answering |

`<id>` and `<subject>` are base64url of their JSON, so a brace cannot walk
into the hash tag and two values differing only in a lone surrogate cannot
share a key. A grant's three keys share a tag and are written by one script; a
subject's index is a key of its own and is never touched by a script that
touches a record — which is what lets a deployment's grants spread across a
Cluster rather than pile onto the one node a namespace-wide tag would name. So
a member is reserved before its record is written, at the horizon the record
will have, its score only moves forward, and it is pruned by that horizon and
never by whether the record is there.

Every write is one guarded script, and a refused one says only that it was
refused: the record may change again before the caller looks, so the port
re-reads. Nothing deletes a record because of the time its caller passed —
what a caller is told is judged on the time it passes, and what Redis reclaims
is judged by Redis.

The credential is sealed under a key **ring**: the first key seals, every
configured key opens, and the envelope names the one that sealed it, so a key
can be introduced without re-sealing grants that are paused. A key that is not
in the ring reads as `key_unavailable` — a configuration problem an operator
undoes by putting it back — and is told apart from a credential that will
never open again. Nothing is ever deleted on a read. Rotate by adding the new
key last, then moving it first, and keep the old one listed for 365 days after
the last replica that sealed with it stopped — the procedure, and why it is
the ceiling and not `maxExpiresIn`, is in `docs/operator-runbook.md`.

The index (`idx:`) is what lets `removeBySid` name the keys it must delete
instead of hunting for them, at a cost of O(that session's federations). Before
v0.10 the only way to find them was `SCAN MATCH ${keyPrefix}${sid}:*` over the
entire database — O(keys in Redis), on an end-user action, on the connection
every other adapter here shares (#291).

Two improvements do apply unconditionally, flag or not: reads are paged
(`SSCAN`, `HSCAN`, `ZRANGE` by rank), so no single command's reply grows with
how heavily linked a session is; and removals use `UNLINK`, so the shared
connection is not blocked while Redis frees the values.

### `scanFallback` — a migration flag, not a tuning knob

Records written before v0.10 have no index entry. An index-only `removeBySid`
would walk past them and leave a logged-out session's **upstream IdP refresh
tokens** in Redis until the store TTL expired them. So `scanFallback` (option
on the builder, `redisFederationTokenStore.scanFallback` in the module config)
keeps the old pattern scan running after the index-driven removal.

- **Default `true`,** because an upgrade that changes no configuration must not
  silently orphan tokens. It is the safe default, not the fast one.
- **What it costs while on:** one keyspace scan per `removeBySid` — exactly the
  O(keyspace) work #291 is about. The index-driven removal runs first
  regardless, so the *deletes* are always bounded and the paging and `UNLINK`
  improvements are always in effect; but the scan is still there, so a
  deployment on defaults has **not** yet got the headline fix.
- **When to set it to `false`:** once no session predating the upgrade can
  still exist — that is, once `ttl` (default 24 h) has elapsed since the last
  replica running the previous release stopped writing. A deployment whose
  Redis held no federation records before the upgrade (a fresh database, or
  `federationTokenStore` newly enabled) can set it to `false` immediately.
- **When it goes away:** the flag and the scan path are removed together once
  the migration window has closed (see the root CHANGELOG for the release that
  performs the removal) — at which point the index-only behaviour becomes
  unconditional and `scanIterator` leaves `FederationTokenStoreClient`.

## Device authorizations share one slot

`redisDeviceCodeStoreModule` (#433) keeps a pending RFC 8628 authorization
as two keys:

| Key | Type | Holds |
| --- | --- | --- |
| `${keyPrefix}{devauth}:code:${device_code}` | hash | the record — status, expiry, interval, scope, subject |
| `${keyPrefix}{devauth}:user:${user_code}` | string | the `device_code` it belongs to |

`keyPrefix` is `redisDeviceCodeStore.keyPrefix` (default `devauth:`); the
`{devauth}` segment is a constant **hash tag**. The record is keyed by the
device code, `approve`/`deny` arrive with the user code, and both are
independent random values — so a script that follows the index to the record
has to find both keys in the one slot Redis Cluster routed it to. The tag is
what puts them there, and the cost is that **every device authorization
lands on the same slot**. For this flow's volume — a human-initiated
ceremony, not per-request traffic — that is an acceptable trade, but it is a
real one. The alternative, storing the record twice under each key, would
make `approve` and `poll` non-atomic across the pair, which is precisely
what the `DeviceCodeStore` port forbids.

Each port operation is one Lua script (EVALSHA-first, `EVAL` on `NOSCRIPT`,
like the others in this package), so `poll` reads the status and consumes an
approval indivisibly — the conformance suite's "two polls racing for the
same approval" case runs against a real Redis in this package's tests, and
that is the case a `HGETALL`-then-`DEL` implementation fails. Both keys
carry the authorization's `expiresAtMs` as their TTL so Redis reclaims them,
but `poll` still answers `expired` from the timestamp: a record inside its
TTL whose deadline has passed on the caller's clock expires, and is dropped.

## Consent records and parked requests

`redisConsentStoreModule` (#561) provides both slots the consent step needs —
one switch, as core's memory module is, because `createOAuthRouter` refuses a
composition with one and not the other. Its keys:

| Key | Type | Holds |
| --- | --- | --- |
| `${keyPrefix}rec:${len}:${sub}\|${len}:${clientId}` | hash | a consent record — `scopes` (JSON array), `grantedAt`, `expiresAt` when it has one |
| `${keyPrefix}{pending}:ch:${challenge}` | hash | a parked `/authorize` request, its `sessionId` and `expiresAt` |
| `${keyPrefix}{pending}:sess:${sessionId}` | sorted set | that session's challenges, scored by the order they were parked |

`keyPrefix` is `redisConsentStore.keyPrefix` (default `consent:`). A consent
record is one key, and every script over it touches that key alone, so consent
records spread across a Cluster like any other key; the pair is length-prefixed,
as the challenge and replay stores encode theirs, so no subject or client id can
spell another pair's key. A parked request and its session's index share the
constant **`{pending}` hash tag**: `consume` arrives with the challenge alone and
takes the request out of the index in the same script, so the two keys must be in
one slot — and every parked request therefore lands on the same slot, the trade
the device-code store makes and for the same reason (a human-paced ceremony,
bounded per session and gone in minutes).

Each operation that must be indivisible is one Lua script: `grant` computes the
union with what is recorded (only while that record is live), `consume` reads the
request and removes it with its index entry, and parking a request holds its
session to `PENDING_CONSENT_PER_SESSION_LIMIT`, dropping that session's expired
requests before evicting the first-parked. The conformance suites for both ports
run against a real Redis in this package's tests, racing cases included.

A stored value that is not the shape the port declares — a missing or non-string
field, a parked request naming a challenge other than its key's, JSON that does
not parse — reads as **absent**, never as a throw: corruption is not an outage,
and "no consent" / "no pending request" is the answer that fails closed. A corrupt
parked request is reclaimed with its index entry (by the consume script, or after
a read by a compare-and-delete); a corrupt consent record is given no weight by
the next grant, which replaces it.

Expiry is judged by the record's own `expiresAt` against the caller's clock, never
by a key's TTL. The TTL a write sets — relative, `PEXPIRE`, so the skew between
the writing replica and Redis cannot move it — runs `CONSENT_EXPIRY_SLACK_MS`
(five minutes, the JWT verifier's default clock-skew allowance) past that expiry,
so it only reclaims records nobody reads again: a replica whose clock runs
behind the writer's by less than that still finds a record it holds to be live. A consent recorded until
revoked — what `POST /oauth/consent` writes — has no TTL at all, including when
an earlier grant for the pair had one.

## Internal helpers

`src/internal/lock.mts` (`createRedisLock`) and `src/internal/crypto.mts`
(the AES-256-GCM helpers) are private to this package.
The lock embeds federation-tokens-specific options (`{ sid,
federationName }`) in `AcquireLockOptions` and is not currently
backend-agnostic; a public generic-lock API is on the roadmap for
v0.6+.

Since #293 the federation-token store seals the **whole** envelope —
`rawParams`, `tokenType`, `scope` and the access-token expiry included, not
just the three token fields — as one ciphertext, `{ "v": 2, "c": "…" }`, bound
to its own Redis key as additional authenticated data (`allow-plaintext`,
development only, writes `{ "v": 2, "p": { … } }`). A record without that
wrapper is the pre-#293 per-field shape and is dropped on first read: `get`
returns `null`, the key and its index member go, and the user re-federates.
There is no dual-read path by design.

`src/internal/redisSidHash.mts`, `redisSidSortedSet.mts` and `redisSidSet.mts`
are the three sid-keyed structures the session and federation adapters are
built from — same `${keyPrefix}${sid}` layout and TTL contract, different Redis
type (HASH / ZSET / SET).
