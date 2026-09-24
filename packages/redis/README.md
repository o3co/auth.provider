# @o3co/auth-provider-redis

Last updated: 2026-09-25

Redis-backed implementations of the store ports `@o3co/auth-provider-core`
declares, a `defineModule` manifest for each, and the wrappers that turn one
ioredis connection into every client they need.

## Responsibility

**Role.** The shared-state backend of a scaled deployment. Core declares each
store port (`ChallengeStore`, `UserSessionStore`, `FederationGrantStore`, …)
and ships an in-process implementation that is correct on one replica; those
whose state must be shared declare themselves replica-unsafe and are refused
under `deployment.mode = "multi"`. This package supplies the implementation
every replica shares, and the manifest that puts it in the port's slot.

**Owns:**

- one adapter per Redis-backed port (listed under [Adapters](#adapters)): its
  key layout, its Lua scripts, its TTL rules;
- the per-purpose backing-client interfaces those adapters call
  ([`src/clients.mts`](src/clients.mts)) — the Redis-command vocabulary lives
  here, not in core;
- `makeIoredisClients` and the per-store ioredis wrappers, on the `/ioredis`
  subpath;
- sealing the federation-token and federation-grant records at rest, and the
  guard that refuses `allow-plaintext` in a production or staging environment
  and under `deployment.mode = "multi"`.

**Does not own:**

- the ports and what they promise — core declares them, and core's
  conformance suites hold these adapters to them ([Contract tests](#contract-tests));
- the flows built on the stores: refresh-token rotation and revocation
  (`RefreshTokenFamilyRotation` / `RefreshTokenFamilyRevocation`) are core's,
  over whichever `RefreshTokenFamilyStore` is wired; the logout cascade and
  subject-wide revocation belong to core and the route packages;
- the connection: the composition root opens the ioredis `Redis` instance,
  chooses its options and attaches its `error` listener;
- the `express-session` store behind the browser cookie. That is
  `@o3co/auth-provider-session`'s, over connect-redis and a node-redis client
  of its own.

**Why a separate package.** It keeps a database driver and its vocabulary out
of core — CI refuses an `ioredis` or `redis` import in core's source — so core
stays backend-agnostic, and a composition root of your own that runs on one
replica can leave Redis out entirely. The standalone template cannot: it keeps
its refresh-token families in Redis in every deployment. An adapter for another
backend is a package of its own beside this one, implementing the same ports.

## Install

```sh
npm install @o3co/auth-provider-redis @o3co/auth-provider-core
# and, for makeIoredisClients and the other wrappers on the /ioredis entry:
npm install ioredis@^6.0.0
```

Peer dependency: `@o3co/auth-provider-core`. Optional peer dependency:
`ioredis@^6.0.0`, which only the `@o3co/auth-provider-redis/ioredis` entry
imports (see [Entry points](#entry-points)). The package depends on `zod`.

## Requirements

- **Node.js** `>=22.0.0`
- **Redis server** `>=7.2 LTS` — the session adapters issue a
  `PEXPIREAT … NX` + `PEXPIREAT … GT` pair for safe concurrent TTL writes.
  NX sets the TTL on first write because a bare `… GT` silently no-ops on a
  key with no existing TTL; GT then prevents truncation under
  stale-`expiresAt` concurrent writes. Both flags require Redis 7.0+; the
  tested floor is 7.2 LTS. Redis 6.x is not supported. Tested against:
  - AWS ElastiCache for Redis 7.2
  - Upstash Redis (7.2 compatible)
  - Redis Cloud 7.2
  - Self-managed `redis:7.2-alpine`
- **Redis Lua scripting** (`EVAL` / `EVALSHA`). The clients this package
  builds run their indivisible operations as scripts: the rate limiter's
  increment-with-TTL, the federation-token lock release, the subject session
  index and revocation watermarks, and the indivisible operations of the
  device-code, consent, pending-consent, federation-grant and
  federation-grant intent stores. Lua is enabled by default on Redis
  standalone and Sentinel. **Redis Cluster with Lua scripting disabled is not
  supported by the bundled clients** — enable scripting, or implement the
  per-purpose client interfaces ([Backing-client contract](#backing-client-contract))
  over another atomic primitive yourself.

## Adapters

Each one implements a port core declares; the slot name is in parentheses.

- `ChallengeStore` (`challengeStore`)
- `ReplaySeenSet` (`replaySeenSet`) — single-use records: `private_key_jwt`
  `jti`s, consumed WebAuthn challenges, and every proof
  `@o3co/auth-provider-dpop` accepts (under `dpop-proof:<jkt>`). The
  in-process alternative forks per replica, so a captured assertion or proof
  replays once against each; core refuses that one under
  `deployment.mode = "multi"`.
- `AccessTokenDenylist` (`accessTokenDenylist`) — the store behind RFC 7009
  access-token revocation. The in-process alternative forks per replica, so a
  token revoked on one replica keeps working on the others; core refuses that
  one under `deployment.mode = "multi"` (#277).
- `RefreshTokenFamilyStore` (`refreshTokenFamilyStore`) — the store only.
  Rotation and revocation are core's processes over it.
- `UserSessionStore`, `SessionRPRegistry`, `SessionFamilyIndex`,
  `SessionFederationIndex`, `SubjectSessionIndex`, `SubjectRevocation` — the
  six user-session and subject-revocation stores, installed together by
  `redisSessionStoresModule`.
- `FederationTokenStore` (`federationTokenStore`) — the upstream IdP tokens
  held for a session. See [Federation-token keys and logout](#federation-token-keys-and-logout).
- `FederationGrantStore` (`federationGrantStore`) and
  `FederationGrantIntentStore` (`federationGrantIntentStore`) — federation
  grants (#593): a user's standing consent that a client may obtain upstream
  tokens with no session behind the call, and the records of acquiring one.
  See [Federation grants](#federation-grants).
- `RateLimiter` (`rateLimiter`)
- `CodeRepository` (`codeRepository`) — authorization codes.
- `DeviceCodeStore` (`deviceCodeStore`) — pending RFC 8628 device
  authorizations for `@o3co/auth-provider-device-grant`. The in-process
  alternative forks per replica — the human approves on the replica that
  served the verification page while the device polls one that has never
  heard of the code — so core refuses it under `deployment.mode = "multi"`
  (#433). See [Device authorizations share one slot](#device-authorizations-share-one-slot)
  before choosing it.
- `ConsentStore` / `PendingConsentStore` (`consentStore`, `pendingConsentStore`)
  — the consent step for clients that are not first-party: what a user agreed
  a client may obtain, and the `/authorize` request parked while the consent
  page asks. Core's in-process pair forks per replica and is refused under
  `deployment.mode = "multi"`. See [Consent records and parked requests](#consent-records-and-parked-requests).

## Entry points

| Import | What it holds | Why it is separate |
| --- | --- | --- |
| `@o3co/auth-provider-redis` | The adapters, their modules and builders, and the backing-client interfaces | Imports no driver: a consumer that writes its own clients never has `ioredis` in its type closure |
| `@o3co/auth-provider-redis/ioredis` | `makeIoredisClients` and the federation-grant client wrappers | The only entry that needs `ioredis` (an optional peer) installed |

The exports are listed in [`src/index.mts`](src/index.mts) and
[`src/ioredis.mts`](src/ioredis.mts).

## Backing-client contract

Each adapter consumes a **per-purpose backing-client interface** declared in
[`src/clients.mts`](src/clients.mts) — `ChallengeStoreClient`,
`FederationTokenStoreClient`, `RateLimiterClient` and so on. Core does not
declare them: they are expressed in Redis-command terms, so they belong to the
Redis adapter package. Each declares only the methods its adapter calls, and
where an operation must be indivisible the interface makes it one method — the
rate limiter's client increments and sets the TTL in a single call (#269), so
an implementation cannot leave a counter with no expiry. Wire whichever driver
satisfies the interfaces; a non-Redis backend writes its own ports' adapters
rather than implementing these.

For the common case of one ioredis connection serving every Redis-backed
adapter, `makeIoredisClients(io)` returns every client slot the modules below
require except the two federation-grant ones:

```ts
import { Redis } from "ioredis";
import { createApp, loggableError } from "@o3co/auth-provider-core";
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
// refresh rotation. Log the projection, not the error (see below).
io.on("error", (err) => logger.error({ err: loggableError(err) }, "redis_client_error"));
const clients = makeIoredisClients(io, { logger });

const handle = await createApp({
    modules: [redisChallengeStoreModule /* + others */],
    bootstrapComponents: { config, pathResolver, ...clients },
});
```

What reaches a log is core's [`loggableError`](../core/README.md#logger)
projection of an error, never the error. ioredis puts the command a reply
answered on the error, arguments included: when the server refuses the
configured password, that is the handshake — `AUTH` and the password — on
`command.args`, and a logger that serialises the error writes it out. The
projection keeps the command's name alone (`command: { name: "hello" }`), so
the line still says which command failed. The connections
`makeIoredisClients` opens for refresh rotation log
`redis_duplicate_connection_error` through the projection, and a stored
authorization code, user session or RP record that does not parse is logged as
the parser error's name and position (`RedisCodeRepository: corrupted data for
code`, `user_session_corrupt_envelope`, `session_rp_registry_corrupt_envelope`),
never the stored text the parser's message quotes.

The federation-grant clients are built separately,
`makeIoredisFederationGrantStoreClient(io)` and
`makeIoredisFederationGrantIntentStoreClient(io)`, so that a Cluster deployment
can give the grants a connection of their own; they may equally be the same
`io`.

For mixed-backend deployments (another backend for `ChallengeStore`, Redis for
`FederationTokenStore`), wire each per-purpose slot individually instead of
spreading.

### Failure timing

`makeIoredisClients` derives every client from the one connection you hand it
and opens none of its own (the exception is
`refreshTokenFamilyClient.duplicate()`, one per refresh rotation).
Connection-level ioredis options are therefore shared by every client it
returns, and the ones governing how a partition *ends* are the ones worth
setting deliberately:

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

## Modules and builders

Each adapter ships in up to two forms:

- A **`defineModule` manifest** (`redisChallengeStoreModule`,
  `redisFederationTokenStoreModule`, …) for declarative wiring through
  `createApp({ modules: [...] })`. This is what the standalone template uses.
  The two stores that seal records at rest also have a `…ModuleFor({ environment })`
  form, `redisFederationTokenStoreModuleFor` and
  `redisFederationGrantStoreModuleFor`, for a composition root that selects its
  config by a name other than `NODE_ENV` (the standalone's `CONFIG_ENV`): the
  plaintext guard reads that name in addition to `NODE_ENV`, and
  `deployment.mode` off the config — `"multi"` refuses plaintext in every
  environment (#473).
- An **`AdapterBuilder`** (`redisChallengeStoreBuilder`,
  `redisCodeRepositoryBuilder`, …) for a composition root that selects a
  backend at runtime through core's `AdapterFactory`:
  `factory.register("redis", redisXxxBuilder)`, then
  `factory.create({ type: "redis", client, ... })`.

| Module | Requires | Provides | Config key | Builder |
| --- | --- | --- | --- | --- |
| `redisChallengeStoreModule` | `challengeStoreClient` | `challengeStore` | `redisChallengeStore` | `redisChallengeStoreBuilder` |
| `redisReplaySeenSetModule` | `replaySeenSetClient` | `replaySeenSet` | `redisReplaySeenSet` | `redisReplaySeenSetBuilder` |
| `redisAccessTokenDenylistModule` | `accessTokenDenylistClient` | `accessTokenDenylist` | `redisAccessTokenDenylist` | `redisAccessTokenDenylistBuilder` |
| `redisRefreshTokenFamilyStoreModule` | `refreshTokenFamilyClient` | `refreshTokenFamilyStore` | `redisRefreshTokenFamilyStore` | `redisRefreshTokenFamilyStoreBuilder` |
| `redisSessionStoresModule` | the six session/subject clients | the six session/subject stores | `redisSessionStores` | per-store builders |
| `redisFederationTokenStoreModule` | `federationTokenStoreClient` | `federationTokenStore` | `redisFederationTokenStore` | `redisFederationTokenStoreBuilder` |
| `redisFederationGrantStoreModule` | `federationGrantStoreClient` | `federationGrantStore` | `redisFederationGrantStore`, `federationGrants` | — |
| `redisFederationGrantIntentStoreModule` | `federationGrantIntentStoreClient` | `federationGrantIntentStore` | `redisFederationGrantStore` (`keyPrefix`) | — |
| `redisRateLimiterModule` | `rateLimiterClient` | `rateLimiter` | `redisRateLimiter` | `redisRateLimiterBuilder` |
| `redisCodeRepositoryModule` | `codeRepositoryClient` | `codeRepository` | `redisCodeRepository` | `redisCodeRepositoryBuilder` |
| `redisDeviceCodeStoreModule` | `deviceCodeStoreClient` | `deviceCodeStore` | `redisDeviceCodeStore` | `redisDeviceCodeStoreBuilder` |
| `redisConsentStoreModule` | `consentStoreClient`, `pendingConsentStoreClient` | `consentStore`, `pendingConsentStore` | `redisConsentStore` | `redisConsentStoreBuilder`, `redisPendingConsentStoreBuilder` |

Every module also requires `config`. The `*Client` column is the slot
`makeIoredisClients` fills, except the two federation-grant clients (see
above); a composition that wires a module without providing its client slot
fails stage-1 boot with `missing-required-component` — named at boot, not at
the first command.

## Expiries and key TTLs

Every adapter turns the expiry or lifetime it is handed into a key TTL by one
rule, and the core ports state the same refusals so the in-process adapters
give the same answers:

- **Whole milliseconds, rounded up.** `PX` and `PEXPIREAT` take whole
  milliseconds and Redis refuses anything else. A fractional expiry — a JWT
  `NumericDate` times 1000, a lifetime configured in fractional seconds — is
  rounded up, so a key outlives the instant it was asked to live until by
  under a millisecond rather than dying before it.
- **A non-finite expiry is refused before Redis is asked**, with a
  `RangeError`: NaN (an Invalid Date, an unset setting) or ±Infinity.
  `NaN <= now` is false, so such a value slipped past every "already expired"
  check and reached Redis as `PX NaN` — and where a script writes its record
  before it sets the deadline, a refused deadline left the record with no TTL
  at all.

| Adapter | Refused with a `RangeError` | Sent to Redis |
| --- | --- | --- |
| `ChallengeStore.issue`, `ReplaySeenSet.markSeen`, `AccessTokenDenylist.add` | a non-finite `expiresAtMs` | `PX` = the remaining life, rounded up |
| `RefreshTokenFamilyStore.registerFamily`, `updateFamily` | a non-finite `expiresAtMs`, registered or committed | `PX` = the remaining life, rounded up; the stored `expiresAtMs` is the rounded expiry, since the reader takes whole milliseconds only |
| `DeviceCodeStore.create` | a non-finite `expiresAtMs` | `PEXPIREAT` = the expiry rounded up; the record keeps the exact expiry `poll` answers from |
| `CodeRepository.createCode` | an `expiresIn` that is not a positive finite number of seconds | `PX` = `expiresIn` × 1000, rounded up |
| `FederationTokenStore` | a `ttl` that is not a positive finite number (at construction) | `PX` and the index TTL = `ttl` × 1000, rounded up |
| The federation-token lock (`acquireLock`) | a `ttlMs` that is not a positive finite number, a `waitForMs` that is not a non-negative finite one | `PX` = `ttlMs`, rounded up |
| `UserSessionStore.create` | an Invalid Date `expiresAt` | `PX` = the remaining life (a `Date` is whole milliseconds) |
| `SessionRPRegistry.registerRP`, `SessionFamilyIndex.addFamilyId`, `SessionFederationIndex.addFederation`, `SubjectSessionIndex.addSid` | an Invalid Date `expiresAt` | `PEXPIREAT` = the session's `expiresAt` |
| `ConsentStore.grant`, `PendingConsentStore.set` | a non-finite `expiresAt` (a consent with none is `undefined`, kept until revoked) | `PEXPIRE` = the remaining life, rounded up, plus the five-minute slack |

[`px-rounding.test.mts`](__tests__/px-rounding.test.mts) pins both halves for
each adapter with a recording client: the contract suites cannot tell
`Math.ceil` from `Math.round` against a real Redis, where the difference is
under a millisecond.

## Federation-token keys and logout

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

The index (`idx:`) is what lets `removeBySid` name the keys it must delete
instead of hunting for them, at a cost of O(that session's federations).
Without it the only way to find them is `SCAN MATCH ${keyPrefix}${sid}:*` over
the entire database — O(keys in Redis), on an end-user action, on the
connection every other adapter here shares (#291).

Two improvements apply unconditionally, flag or not: reads are paged (`SSCAN`,
`HSCAN`, `ZRANGE` by rank), so no single command's reply grows with how
heavily linked a session is; and removals use `UNLINK`, so the shared
connection is not blocked while Redis frees the values.

### `scanFallback` — a migration flag, not a tuning knob

Records written by releases before v0.10 have no index entry. An index-only
`removeBySid` would walk past them and leave a logged-out session's
**upstream IdP refresh tokens** in Redis until the store TTL expired them. So
`scanFallback` (option on the builder, `redisFederationTokenStore.scanFallback`
in the module config) keeps the pattern scan running after the index-driven
removal.

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
  the migration window has closed (the root CHANGELOG names the release that
  performs the removal) — at which point the index-only behaviour becomes
  unconditional and `scanIterator` leaves `FederationTokenStoreClient`.

### The sealed envelope

The federation-token store seals the **whole** envelope (#293) — `tokenType`,
`scope`, `grantedScope` and the access-token expiry included, not just the
three token fields — as one ciphertext, `{ "v": 2, "c": "…" }`, bound to its
own Redis key as additional authenticated data (`allow-plaintext`, development
only, writes `{ "v": 2, "p": { … } }`). A record without that wrapper — the
per-field shape of earlier releases — is dropped on first read: `get` returns
`null`, the key and its index member go, and the user re-federates. There is
no dual-read path by design.

## Federation grants

Their own keyspace, because what they hold outlives every session: default
prefix `fg:` (`redisFederationGrantStore.keyPrefix`).

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
the ceiling and not `maxExpiresIn`, is in the
[operator runbook](../../docs/operator-runbook.md).

**Acquisition's records share the prefix.** The intent store keeps the intent
a backend lodged, the consent challenge and the connect transaction under
`<prefix>{intents}:…`, beside the grants, and reads the same
`redisFederationGrantStore.keyPrefix` — a deployment that moves one namespace
moves both. It is its own module so that grants can live in Redis while
acquisition stays in memory on a single replica (a restart then loses flows in
progress and nothing else); nothing spans the two keyspaces.

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
carry the authorization's `expiresAtMs`, rounded up to a whole millisecond,
as their deadline so Redis reclaims them, but `poll` still answers `expired`
from the record's own exact timestamp: a record inside its TTL whose deadline
has passed on the caller's clock expires, and is dropped.

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
behind the writer's by less than that still finds a record it holds to be live.
A consent recorded until revoked — what `POST /oauth/consent` writes — has no TTL
at all, including when an earlier grant for the pair had one.

## Contract tests

Each adapter whose port has a core conformance suite is run through that
suite against a real Redis (Testcontainers) in [`__tests__/`](__tests__/). One
container serves the whole run, started before any test file by
[`__tests__/support/redis-container.global.mts`](__tests__/support/redis-container.global.mts),
and each file takes a logical database of its own from
[`__tests__/support/redis.mts`](__tests__/support/redis.mts) — one container
per file paid Testcontainers' fixed ten-second port-binding wait once per file,
and a loaded machine failed files on it. A test that waits for something to
expire in Redis waits on the server's clock (`serverClock` there), not on a
sleep on the host's. A
contract file cannot be imported across a package boundary, so the suites
there are copies of core's; [`contract-copies-parity.test.mts`](__tests__/contract-copies-parity.test.mts)
and the per-port `*-parity.test.mts` tests fail when a copy differs from its
core original anywhere below its imports, and when no Redis test runs it.
Which ports have a suite, and the one Redis adapter the suites do not run
against (`AccessTokenDenylist`, whose expiry is Redis's own key TTL and cannot
follow the suite's fake clock), are in
[docs/adapter-surface.md](../../docs/adapter-surface.md). The adapters whose
ports have no core suite — `FederationTokenStore`, `RateLimiter`,
`CodeRepository` — are covered by their own tests here.

## Source layout

Each adapter, with its module and builder, is one file in `src/`, named after
its port. Two directories hold what several of them share:

- **`src/modules/`** — modules that bundle more than one store. Every other
  module is defined beside the one store it provides; `redisSessionStoresModule`
  installs six, with one key scheme across them, so it has a file of its own.
- **`src/internal/`** — helpers no consumer imports, and which the package's
  exports do not reach: the advisory lock (its options carry the federation
  token's `{ sid, federationName }`, so it is not a general-purpose lock), the
  AES-256-GCM sealing, the plaintext guard both sealing stores share (one
  escape hatch, `FEDERATION_TOKENS_ALLOW_INSECURE=1`, for both), the
  federation-grant codecs and lock, and the three sid-keyed structures (HASH,
  ZSET, SET) the session and federation adapters are built from — same
  `${keyPrefix}${sid}` layout and TTL contract, different Redis type.
