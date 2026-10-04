# @o3co/auth-provider-redis

Last updated: 2026-10-05

Redis-backed implementations of the store ports `@o3co/auth-provider-core`
declares, a `defineModule` manifest for each, and the wrappers that turn one
ioredis connection into every client they need.

## Responsibility

**Role.** The shared-state backend of a scaled deployment. Core declares each
store port (`ChallengeStore`, `UserSessionStore`, `FederationGrantStore`, …)
and ships an in-process implementation that is correct on one replica; those
whose state must be shared declare themselves replica-unsafe and are refused
under `core.deployment.mode = "multi"`. This package supplies the implementation
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
  and under `core.deployment.mode = "multi"`.

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
  device-code, consent, pending-consent, federation-grant,
  federation-grant intent and MFA stores. Lua is enabled by default on Redis
  standalone and Sentinel. **Redis Cluster with Lua scripting disabled is not
  supported by the bundled clients** — enable scripting, or implement the
  per-purpose client interfaces ([Backing-client contract](#backing-client-contract))
  over another atomic primitive yourself.
- **A `maxmemory`, and an eviction policy that cannot drop a replay record.**
  The replay seen-set writes a record for every DPoP proof it sees — at the
  token endpoint before its rate limit runs, at a protected resource before
  the access token is verified — and keeps it for
  `dpop.replayStoreTtlSeconds` (300 s by default), so its size
  follows the request rate, whoever sends the requests. Set `maxmemory` so a
  flood cannot take the server's host down, and choose what happens at it.
  Under `noeviction` a full server refuses the write, and every consumer
  refuses what it was recording as an outage, `503 temporarily_unavailable`:
  it fails closed. An evicting policy keeps accepting writes by deleting
  keys, and a deleted replay record is a proof or assertion that can be
  replayed within its window: `allkeys-lru` (and every `allkeys-*` policy)
  can evict any key, a replay record included, and the `volatile-*` policies
  evict keys that carry a TTL, which every replay record does. Keep the
  seen-set on a server whose policy is `noeviction`, or on one sized never
  to reach `maxmemory`. Core's in-process seen-set has a cap of its own
  (`core-replay-seen-set-memory.maxEntries`, a million records by default) and
  refuses at it the same way, with a reserve this adapter does not have:
  DPoP proofs fill at most 90% of it, so a DPoP flood leaves room for
  `private_key_jwt` and WebAuthn. A Redis at `maxmemory` refuses every
  consumer alike — keep the seen-set's instance sized for the flood, or on
  one of its own.
- **For the family index's "ended" mark, reads and writes that are
  linearizable, and reads served by the primary** (core's
  `SupportsSessionEnd`): that a logout and a grant on one session never both
  miss each other holds only while every operation sees each write completed
  before it. Redis's asynchronous replication does not hold that across a
  failover, where a promoted replica may lack a write the old primary
  acknowledged, and a read answered by a replica does not either.
  The RP registry rests on the same assumption (core's `SessionRPRegistry`):
  a `registerRP` a promoted replica lost, or a `listRPs` a replica answered,
  leaves that RP out of the logout fan-out.
- **For the MFA stores, a server that keeps what it is written** (the MFA
  ADR's D12). An enrolled second factor lost to an eviction or a restart
  reads as "never enrolled", and whoever holds the password can then bind
  their own; the email proof an operator reset requires is lost the same way.
  Give them `noeviction` and AOF (`appendfsync everysec`), preferably on a
  database or instance of their own. A `volatile-*` policy never picks the
  factors or the requirement, which carry no TTL, but it may pick an emptied
  factor set's tombstone, which then reads as never written before its 24
  hours are up, and a subject's lock state once that carries one, ending a
  hold on guessable proofs early. Both modules check at boot (see
  [MFA stores](#mfa-stores)). The factor store also assumes acknowledged
  writes are not rolled back on failover, and that the app's and Redis's
  clocks agree within 1 second (see [MFA stores](#mfa-stores), "The factor
  set's generation").
- **For the federation token store, `noeviction`.** Each `attach`,
  `replaceIf` and `removeIf` keeps its answer for a few seconds under a
  replay key with a TTL (see [Conditional writes](#conditional-writes)). A
  `volatile-*` or `allkeys-*` policy may evict one early. A copy of an
  `attach` the driver then sends again within its deadline writes again: it
  overwrites a newer record, or restores a removed one (a logged-out
  session's upstream refresh token included). A copy of a `replaceIf` or
  `removeIf` writes nothing, but answers `conflict` or `missing` for a write
  that landed. The module refuses an eviction policy at boot; give the store
  a server of its own if the rest of your Redis may not run `noeviction`.

## Adapters

Each one implements a port core declares; the slot name is in parentheses.

- `ChallengeStore` (`challengeStore`)
- `ReplaySeenSet` (`replaySeenSet`) — single-use records: `private_key_jwt`
  `jti`s, consumed WebAuthn challenges, and every proof
  `@o3co/auth-provider-dpop` accepts (under `dpop-proof:<jkt>`). The
  in-process alternative forks per replica, so a captured assertion or proof
  replays once against each; core refuses that one under
  `core.deployment.mode = "multi"`.
- `AccessTokenDenylist` (`accessTokenDenylist`) — the store behind RFC 7009
  access-token revocation. The in-process alternative forks per replica, so a
  token revoked on one replica keeps working on the others; core refuses that
  one under `core.deployment.mode = "multi"` (#277).
- `RefreshTokenFamilyStore` (`refreshTokenFamilyStore`) — the store only.
  Rotation and revocation are core's processes over it. A family's key lives
  until the `expiresAtMs` last committed to it: the family's lifetime while
  it is live, and — once core revokes it — until the last access token the
  family could have minted stops being accepted (up to
  `oauth.accessToken.maxExpiresIn` plus about five minutes past the
  revocation), so revoked families' keys outlive their refresh tokens.
- `UserSessionStore`, `SessionRPRegistry`, `SessionFamilyIndex`,
  `SessionFederationIndex`, `SubjectSessionIndex`, `SubjectRevocation` — the
  six user-session and subject-revocation stores, installed together by
  `redisSessionStoresModule`. The `UserSessionStore` has the step-up
  capability (`recordSecondFactor`, the MFA ADR's D9): it reads the session,
  computes the next one with core's `sessionAfterSecondFactor` — which splits
  a session written before `authentication` existed — and writes it through
  the client's `replaceIfUnchanged`, a script that `SET`s with `KEEPTTL` only
  while the key still holds what was read, re-reading on a loss at most five
  times before it throws. A second factor never changes how long a session
  lives. The session envelope carries `authentication` as a key of its own:
  an envelope written before it reads as `authentication: undefined` (a
  pre-upgrade session, split as core reads it), a malformed one is refused as
  corrupt, and a release before this one reads the envelope and ignores the
  key. The step-up write rewrites only `amr`, the fields of
  `authentication` this release knows, and `renewalNonce` when the event
  carries one (the MFA ADR's D27: written in the same compare-and-set as the
  escalation, kept by a step-up without one; absent until then, and any
  value that is not a nonce reads the envelope as corrupt; an event whose
  `expectedRenewalNonce` is not the envelope's nonce, judged on the bytes
  the compare-and-set writes over, is answered `null` with nothing written), so what a newer
  release added beside or inside them survives a step-up on a replica not
  yet upgraded. A custom
  `UserSessionStoreClient` implements `replaceIfUnchanged`
  (`makeIoredisClients` does); `createRedisUserSessionStore` refuses a client
  without it when the store is built, naming the method. The envelope carries
  `enrollmentFacts` (`{witness, mailAddress}`, what the login's `User` said for
  a first binding) as a key of its own, left out when the session recorded
  none: an envelope without it reads as a session with none, a malformed one
  is refused as corrupt, and a release before this one ignores the key. A
  step-up keeps it as it was. The `SessionFamilyIndex` has the session-end
  capability (core's `SupportsSessionEnd`) when it is given an
  `endedKeyPrefix` and a `SessionFamilyIndexClient` with `writeEndedMark` and
  `hasEndedMark`, which `makeIoredisClients` provides, and which the module
  and the builder (beside its default `keyPrefix`) give it: the mark is a
  string at `<endedKeyPrefix><sid>` (`ss:fi-ended:` by default) expiring at
  the session's `expiresAt` plus the clock-skew allowance (core's
  `DEFAULT_CLOCK_SKEW_MS`), beside the family set, and `removeBySid` leaves
  it. `endSession` writes the mark, even past `expiresAt`, and then lists;
  `addFamilyIdUnlessEnded` adds, then reads the mark, then its clock, and
  answers `"ended"` once `expiresAt` has passed. Each reply is in before the
  next command is sent, with no script, so the two keys need not share a
  Cluster slot. A client owes the capability writes that resolve only on the
  server's reply and reads served by the primary. An index over a client
  without the two methods, or without an `endedKeyPrefix`, works as before
  without the capability; `createRedisSessionFamilyIndex` refuses an
  `endedKeyPrefix` that overlaps `keyPrefix` (either starting with the
  other). The `SubjectRevocation` store clamps a boundary later than the
  server's `TIME` plus `DEFAULT_CLOCK_SKEW_MS` to that, in the script that
  writes it, and then says so at warn (`subject_revocation_boundary_clamped`,
  with `store`, `subject`, `requestedBefore`, `recordedBefore`) on the
  module's logger, or the builder's `logger` option, else the factory
  context's logger, and `consoleLogger` without one; a failing logger never fails
  the revocation. It clamps through the client's
  `advanceRevocationBoundaries`, which `makeIoredisClients` provides; the store
  refuses, at construction, a custom `SubjectRevocationClient` without it. A
  replica of an older release writes the same stored value, unclamped, until
  it is replaced.
- `FederationTokenStore` (`federationTokenStore`) — the upstream IdP tokens
  held for a session. See [Federation-token keys and logout](#federation-token-keys-and-logout).
- `FederationGrantStore` (`federationGrantStore`) and
  `FederationGrantIntentStore` (`federationGrantIntentStore`) — federation
  grants (#593): a user's standing consent that a client may obtain upstream
  tokens with no session behind the call, and the records of acquiring one.
  See [Federation grants](#federation-grants).
- `RateLimiter` (`rateLimiter`)
- `AttemptCounter` (`attemptCounter`) — the counter behind a verifier's own
  attempt limits, which core's `createAttemptGuard` runs on: one script per
  attempt over a hash per key (the window's count and end). Its keys live
  under their own prefix (`redis-attempt-counter.keyPrefix`, default
  `attempt:`), apart from the rate limiter's, which have the same
  `<tag>:<id>` form under no prefix. A window's end is set on this side's
  clock, the one the guard reads the count on, and the key's TTL is relative
  (`PEXPIRE`: the window's length plus five seconds). A window is running while
  its end is after the caller's clock or its TTL is above those five seconds,
  so neither a server clock set apart nor a replica clock running ahead ends
  one early: a replica ahead past a window's end is answered that end, which
  the guard takes within five seconds and answers `503` beyond, never with a
  fresh window. A forward step of the server's wall clock can still expire
  windows early, as for every key with a TTL. A refused attempt writes nothing, and a reply that is no count
  rejects, which the guard answers `503`. `redisAttemptCounterModule` refuses
  the boot (`attempt-counter-evictable`) on a server whose `maxmemory-policy`
  is not `noeviction`: every window's key carries a TTL, so any evicting policy
  may drop a running window and give its key a fresh one. A policy it cannot
  read is one warning, `attempt_counter_durability_unchecked`, and the boot
  goes on. Give the counter a server, or a database on one, that does not
  evict. Windows do not survive a restart of a server without persistence: each
  key starts a fresh window after one.
- `CodeRepository` (`codeRepository`) — authorization codes.
- `DeviceCodeStore` (`deviceCodeStore`) — pending RFC 8628 device
  authorizations for `@o3co/auth-provider-device-grant`. The in-process
  alternative forks per replica — the human approves on the replica that
  served the verification page while the device polls one that has never
  heard of the code — so core refuses it under `core.deployment.mode = "multi"`
  (#433). See [Device authorizations share one slot](#device-authorizations-share-one-slot)
  before choosing it.
- `MfaFactorStore` (`mfaFactorStore`) and `MfaTransactionStore`
  (`mfaTransactionStore`) — enrolled second factors, and the MFA ceremonies,
  subject lock and email-proof requirement beside them (the MFA ADR's D7, D8,
  D21, D25). The in-process alternatives fork per replica; core refuses them
  under `core.deployment.mode = "multi"`. See [MFA stores](#mfa-stores).
- `ConsentStore` / `PendingConsentStore` (`consentStore`, `pendingConsentStore`)
  — the consent step for clients that are not first-party: what a user agreed
  a client may obtain, and the `/authorize` request parked while the consent
  page asks. Core's in-process pair forks per replica and is refused under
  `core.deployment.mode = "multi"`. See [Consent records and parked requests](#consent-records-and-parked-requests).

## Entry points

| Import | What it holds | Why it is separate |
| --- | --- | --- |
| `@o3co/auth-provider-redis` | The adapters, their modules and builders, and the backing-client interfaces | Imports no driver: a consumer that writes its own clients never has `ioredis` in its type closure |
| `@o3co/auth-provider-redis/ioredis` | `makeIoredisClients`, the federation-grant client wrappers and the MFA stores' (`makeIoredisMfaFactorStoreClient`, `makeIoredisMfaTransactionStoreClient`) | The only entry that needs `ioredis` (an optional peer) installed |

The exports are listed in [`src/index.mts`](src/index.mts) and
[`src/ioredis.mts`](src/ioredis.mts).

## Backing-client contract

Each adapter consumes a **per-purpose backing-client interface**, declared in
[`src/clients/`](src/clients/), one file per store family, and exported from
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
the parser error's name and position, as `err`, never the stored text the
parser's message quotes: `authorization_code_corrupt_record` (error),
`user_session_corrupt_envelope` and `session_rp_registry_corrupt_envelope`
(warn), each with `reason` `json_parse` — or, for a record that parses but is
not one, `shape_invalid` (`identity_fields_missing` for a code without its
client and redirect URI). The stores write them on the logger their module
hands them (the `logger` slot) and on `consoleLogger` when there is none, so
a corrupt record is never unreported.

A `MULTI`/`EXEC` whose queued command Redis refused (`WRONGTYPE`, `OOM`,
`READONLY` …) is thrown as an error that names the operation in fixed words —
`<client>.<method>: a queued command failed inside MULTI/EXEC` — with the
reply error as its `cause`. Redis's text stays off the message, since a
refusal can quote the command's arguments; the projection of the cause is
where an operator reads it.

The federation-grant clients are built separately,
`makeIoredisFederationGrantStoreClient(io)` and
`makeIoredisFederationGrantIntentStoreClient(io)`, so that a Cluster deployment
can give the grants a connection of their own; they may equally be the same
`io`. The MFA stores' clients are in `makeIoredisClients` too, and can also be
built on their own — `makeIoredisMfaFactorStoreClient(io)`,
`makeIoredisMfaTransactionStoreClient(io)` — for the database or instance of
their own that D12 prefers.

A `DeviceCodeStoreClient` of your own writes an approval's `amr` and
`authTimeMs` in `decide`'s same atomic write as the approval itself; one that
does not makes every approval read both as absent.

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
  plaintext guard reads that name in addition to `NODE_ENV`, and the
  replica count from core's `deploymentMode` slot, which both modules require
  and core fills from `core.deployment.mode` — `"multi"` refuses plaintext in every
  environment. A composition root that builds either store itself passes
  `deploymentModeOf(config)` from `@o3co/auth-provider-core` — the reading
  boot fills the slot with — to `resolveRedisFederationGrantStoreOptions` as
  its third argument, and to `createRedisFederationTokenStore` and
  `redisFederationTokenStoreBuilder` as their required `deploymentMode`
  option; a mode that is not `single`, `multi` or `unset`, none included, is
  a TypeError naming the export, before anything is built. Where plaintext goes ahead the guard logs one line on
  the module's optional `logger` slot (`consoleLogger` when it is empty):
  `federation_store_plaintext` (warn, `store`, `mode`) where it is allowed,
  `federation_store_plaintext_override` (error, with the `environment` or
  `deploymentMode` that would have refused it and `override`) where only
  `FEDERATION_TOKENS_ALLOW_INSECURE=1` let it through. The two stores' own
  refusals of a setting they are given and cannot use are `RangeError`s,
  which boot carries as the `cause` of a `provides-factory-failed` BootError
  naming the module: the guard's (`[<store>] mode "allow-plaintext" is
  refused because …`, and `[<store>] mode must be "required" or
  "allow-plaintext"` for a store built directly); the grant store's
  (`federation grant store: mode "required" needs at least one encryption
  key`, `federation grant store: redis-federation-grant-store.encryptionKeys[<i>].key
  must be canonical base64 of 32 bytes`, core's ring rule under
  `federation grant store: redis-federation-grant-store.encryptionKeys`, and
  `federation grant store: keyPrefix may not contain "{" or "}"`); and the
  token store's (`federationTokenStore.redis: encryption.key must be
  canonical base64 of 32 bytes (AES-256), or a Buffer of 32 bytes, when
  encryption.mode is 'required' (the default)`, and its `ttl`). A value a
  module's configuration schema refuses first is `config-validation-failed`
  instead. A builder called without a `client` is a composition fault and
  throws an `Error`, as every builder here does.
- An **`AdapterBuilder`** (`redisChallengeStoreBuilder`,
  `redisCodeRepositoryBuilder`, …) for a composition root that selects a
  backend at runtime through core's `AdapterFactory`:
  `factory.register("redis", redisXxxBuilder)`, then
  `factory.create({ type: "redis", client, ... })`. A builder writes on the
  logger of the factory's context. `redisFederationTokenStoreBuilder` also
  takes `deploymentMode` in that configuration —
  `factory.create({ type: "redis", client, deploymentMode, ... })` — since a
  builder's context carries a lifecycle, readiness and a logger, never the
  mode. `redisCodeRepositoryBuilder` is
  deprecated and says so on every call: `adapter_builder_deprecated` (warn,
  `builder`, `replacement`).

| Module | Requires | Provides | Section | Builder |
| --- | --- | --- | --- | --- |
| `redisChallengeStoreModule` | `challengeStoreClient` | `challengeStore` | `redis-challenge-store` | `redisChallengeStoreBuilder` |
| `redisReplaySeenSetModule` | `replaySeenSetClient` | `replaySeenSet` | `redis-replay-seen-set` | `redisReplaySeenSetBuilder` |
| `redisAccessTokenDenylistModule` | `accessTokenDenylistClient` | `accessTokenDenylist` | `redis-access-token-denylist` | `redisAccessTokenDenylistBuilder` |
| `redisRefreshTokenFamilyStoreModule` | `refreshTokenFamilyClient` | `refreshTokenFamilyStore` | `redis-refresh-token-family-store` | `redisRefreshTokenFamilyStoreBuilder` |
| `redisSessionStoresModule` | the six session/subject clients | the six session/subject stores | `redis-session-stores` | per-store builders |
| `redisFederationTokenStoreModule` | `federationTokenStoreClient` | `federationTokenStore` | `redis-federation-token-store` | `redisFederationTokenStoreBuilder` |
| `redisFederationGrantStoreModule` | `federationGrantStoreClient` | `federationGrantStore` | `redis-federation-grant-store` (`keyPrefix`, `listingAllowanceMs`, `tombstoneRetention`, `encryptionMode`, `encryptionKeys`) | — |
| `redisFederationGrantIntentStoreModule` | `federationGrantIntentStoreClient` | `federationGrantIntentStore` | `redis-federation-grant-intent-store` (`keyPrefix`, default `fg:`) | — |
| `redisRateLimiterModule` | `rateLimiterClient`, `rateLimitBudgetResolver` | `rateLimiter` | `redis-rate-limiter` | `redisRateLimiterBuilder` |
| `redisAttemptCounterModule` | `attemptCounterClient` | `attemptCounter` | `redis-attempt-counter` (`keyPrefix`, default `attempt:`) | — |
| `redisCodeRepositoryModule` | `codeRepositoryClient` | `codeRepository` | `redisCodeRepository` | `redisCodeRepositoryBuilder` |
| `redisDeviceCodeStoreModule` | `deviceCodeStoreClient` | `deviceCodeStore` | `redis-device-code-store` | `redisDeviceCodeStoreBuilder` |
| `redisConsentStoreModule` | `consentStoreClient`, `pendingConsentStoreClient` | `consentStore`, `pendingConsentStore` | `redis-consent-store` | `redisConsentStoreBuilder`, `redisPendingConsentStoreBuilder` |
| `redisMfaFactorStoreModule` | `mfaFactorStoreClient` | `mfaFactorStore` | `redis-mfa-factor-store` (`keyPrefix`, default `mfaf:`) | — |
| `redisMfaTransactionStoreModule` | `mfaTransactionStoreClient` | `mfaTransactionStore` | `redis-mfa-transaction-store` (`keyPrefix`, default `mfat:`) | — |

Each store module but `redisCodeRepositoryModule` reads its own section, named after the module: strict, its defaults and its variables in the package's [`config/reference.conf`](config/reference.conf), which each module declares (`section.reference`) and a composition root layers when it loads any of them. The path a section moved from (`redisConsentStore`, `redisRateLimiter`, `rateLimit.failMode`, the grant store's `federationGrants` keys, …) refuses boot naming the new one, and so does a renamed variable's old name (`RATE_LIMIT_FAIL_MODE`, `REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX` and `_CAS_RETRY_LIMIT`, `FEDERATION_GRANTS_ENCRYPTION_MODE`) unless the new one carries the same value. `redisCodeRepositoryModule` still requires `config` and reads `redisCodeRepository`; the two sealing-store modules require `deploymentMode`. Every module whose stores log also reads
the optional `logger` slot: the two sealing-store modules, for the plaintext
guard's line; `redisSessionStoresModule` and `redisCodeRepositoryModule`, for a
stored record they cannot read; the two MFA store modules, for their boot
durability check's warning. The `*Client` column is the slot
`makeIoredisClients` fills, except the two federation-grant clients (see
above); a composition that wires a module without providing its client slot
fails stage-1 boot with `missing-required-component` — named at boot, not at
the first command.

The rate limiter takes a key's budget from core's one lookup,
`createRateLimitBudgetLookup`: its own `redis-rate-limiter.limits` entry for the
key's prefix, else the budget the prefix's owning module contributed
(`rateLimitBudgetResolver`, read and checked at each check), else its
`defaultLimit`, which it declares (`RateLimiter.defaultLimit`).
`redisRateLimiterModule` answers `redis-rate-limiter.failMode`, its own key, as
the limiter's outage policy (`RateLimiter.failMode`), which the guard applies
while Redis cannot answer; a value other than `"open"` or `"closed"` refuses
boot naming the key, and the default is `closed`.
`redisRateLimiterBuilder` takes the policy as its config's `failMode`, with
the same values; it reads no contributed budget, only the `limits` and
`defaultLimit` it is given. That key governs only a limiter these build: any
other limiter answers its own policy, and boot warns
`rate_limit_fail_mode_not_applied` when `rateLimit.failMode`, the key's old
path, says `"open"` and the wired limiter does not.

## Expiries and key TTLs

Every adapter in this package that hands Redis a deadline — each one in the
table below — turns the expiry or lifetime it is given into a key TTL by one
rule, and the core ports state the same refusals, so the in-process adapters
give the same answers:

- **Whole milliseconds, rounded up.** `PX` and `PEXPIREAT` take whole
  milliseconds and Redis refuses anything else. A fractional expiry — a JWT
  `NumericDate` times 1000, a lifetime in fractional seconds — is rounded up,
  so a key outlives the instant it was asked to live until by under a
  millisecond rather than dying before it.
- **An expiry outside the Date range is refused before Redis is asked**, with
  a `RangeError`: NaN (an Invalid Date, an unset setting), ±Infinity, or a
  finite number past ±8.64e15 ms (core's `isStorableExpiry`; a lifetime must
  end inside it, `isStorableLifetime`). `NaN <= now` is false, so NaN slipped
  past every "already expired" check; past the Date range a number is no
  deadline Redis can take (`1e21` is sent as `1e+21`). Where a script writes
  its record before it sets the deadline, a refused deadline left the record
  with no TTL at all.

| Adapter | Refused | Sent to Redis |
| --- | --- | --- |
| `ChallengeStore.issue`, `ReplaySeenSet.markSeen`, `AccessTokenDenylist.add` | an `expiresAtMs` outside the Date range | `PX` = the remaining life, rounded up |
| `RefreshTokenFamilyStore.registerFamily`, `updateFamily` | an `expiresAtMs` outside the Date range, registered or committed | `PX` = the remaining life, rounded up; the stored `expiresAtMs` is the rounded expiry, since the reader takes whole milliseconds only |
| `DeviceCodeStore.create` | an `expiresAtMs` outside the Date range | `PEXPIREAT` = the expiry rounded up; the record keeps the exact expiry `poll` answers from |
| `CodeRepository.createCode` | an `expiresIn` that is not a positive number of seconds ending within the Date range; a default that is not whole seconds (at construction) | `PX` = `expiresIn` × 1000, rounded up |
| `FederationTokenStore` | a `ttl` that is not a positive number of seconds ending within the Date range (at construction) | `PX` and the index TTL = `ttl` × 1000, rounded up |
| The federation-token lock (`acquireLock`) and the federation-grant refresh lock | a TTL that is not a positive lifetime, or a wait that is not a non-negative one, ending within the Date range | `PX` = the TTL, rounded up |
| `UserSessionStore.create` | an Invalid Date `expiresAt`; an `authTime` or `authentication.mfaAt` that is an Invalid Date or before the epoch (the stored envelope reads back neither), or further ahead of the host's clock than `DEFAULT_CLOCK_SKEW_MS` (one a little ahead is recorded as the host's now) | `PX` = the remaining life (a `Date` is whole milliseconds, and always within the range); `recordSecondFactor` keeps it (`KEEPTTL`) |
| `SessionRPRegistry.registerRP`, `SessionFamilyIndex.addFamilyId`, `addFamilyIdUnlessEnded`, `endSession`, `SessionFederationIndex.addFederation`, `SubjectSessionIndex.addSid` | an Invalid Date `expiresAt` (and, for `registerRP`, an Invalid Date `registeredAt`) | `PEXPIREAT` = the session's `expiresAt`; the family index's "ended" mark `PXAT` = that plus `DEFAULT_CLOCK_SKEW_MS` |
| `ConsentStore.grant`, `PendingConsentStore.set` | an `expiresAt` outside the Date range (a consent with none is `undefined`, kept until revoked) | `PEXPIRE` = the remaining life, rounded up, plus the five-minute slack |
| `SubjectRevocation.revokeBefore`, `revokeSessionsBefore` | a boundary or `expiresAt` that is not a `Date` with a finite time (core's `checkSubjectRevocationInstant`) | `PXAT` = the later of the `expiresAt` asked for and the key's current deadline, raised to the grants floor (the boundary as recorded, clamped, plus the retention) for a full revocation — never lowered |
| `FederationGrantStore`, `FederationGrantIntentStore` | a caller's clock that is an Invalid Date (`RangeError`); an intent or authorization expiry that is not a date writes nothing (`{ ok: false }`, as the port says); a `tombstoneRetentionMs`, `listingAllowanceMs` or `reservationAllowanceMs` that ends past the Date range, at construction. The scripts set a key's deadline after writing it, so a deadline Redis refused left the key with no TTL, and a retention past 2^53 left records that do not read back. The config schemas hold the retention and the listing allowance to one year | `PEXPIREAT` = the record's expiry plus its retention or listing allowance, rounded up (`math.ceil`) inside the script that writes it |
| `MfaTransactionStore.create` | an `expiresAtMs` outside the Date range, or not after this process's clock | `PEXPIREAT` = the expiry rounded up, set once; no later write moves it. The subject lock's keys carry no TTL while a run is counted, and otherwise expire a day after the last failure stops counting (see [MFA stores](#mfa-stores)) |
| `AttemptCounter.consume` | a key or spec core's `isAttemptKey` / `isAttemptSpec` refuses (a window is at most a day), and a clock that answers no instant | `PEXPIRE` = the window's length plus `ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS`, relative so the server's clock does not decide it, set when a window opens; no later attempt moves it |
| `RateLimiter` | at construction, any spec, `defaultLimit` included, that is not a positive whole `limit` and a positive whole `windowSeconds` ending within the Date range: zero, NaN, a fraction, a negative number, or a window past the range. Core's `createRateLimitBudgetLookup` does the check, and the in-process limiter applies the same one. Such a spec is refused, never dropped and never replaced by the default, a looser budget than the operator wrote. Only a `defaultLimit` nobody gave is the built-in 60 per 60 s. The config schemas refuse the same values, and hold a window to one year | `EXPIRE` = `windowSeconds`, set in the same script as the `INCR` |

[`px-rounding.test.mts`](__tests__/px-rounding.test.mts) pins both halves for
each adapter with a recording client: the contract suites cannot tell
`Math.ceil` from `Math.round` against a real Redis, where the difference is
under a millisecond. The device-code, consent and rate-limiter cases past the
Date range also run against a real Redis, where they check that no key is
left behind.

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
| `${keyPrefix}w:{${tag}}:${writeId}` | string | one `attach`'s or conditional write's answer, until the declared clock skew past its deadline (a few seconds). `${tag}` is the part of the record key Redis hashes (its hash tag, else the whole key), so the answer is on the record's Cluster slot, and outside the `${keyPrefix}${sid}:*` a logout's migration scan sweeps. A record key whose braces leave it no hash tag a replay key can carry (a `}` without a tag, or an empty `{}`) is refused (`RangeError`) before any command, by `attach`, `replaceIf` and `removeIf` |

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
`scanFallback` (option on the builder, `redis-federation-token-store.scanFallback`
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
three token fields — as one ciphertext, `{ "v": 2, "g": "…", "c": "…" }`, bound
to its own Redis key as additional authenticated data (`allow-plaintext`,
development only, writes `{ "v": 2, "g": "…", "p": { … } }`). `g` is the
record's store generation, outside the ciphertext (below). A record without
that wrapper — the per-field shape of earlier releases — is dropped on first
read: the read returns `null`, the key goes while it still holds the bytes
read, and the user re-federates. Its index member stays: a concurrent `attach`
may have just added it, and a member naming no key is harmless. There is no
dual-read path by design.

The envelope also carries `obtainedAt`, when the access token's lifetime counts
from, as `obtainedAtMs`, and only when the record has one. A record without it
reads back with `obtainedAt` named, as `undefined`. When the value is not a whole millisecond
within the Date range, the record is deleted on read, like any unreadable
record. Adding it left the wrapper at `v: 2`: the reader ignores envelope keys
it does not know, so a rolling deploy or a rollback reads records either
release wrote, and an older replica's write leaves the field out, which costs
only the refresh damping it feeds. The convention: adding an envelope key keeps
`v: 2`; changing a present key's type or meaning bumps the version.

### Conditional writes

The store's `getVersioned`, `replaceIf` and `removeIf` follow core's
conditional-write convention for a record
([docs/adapter-surface.md, "Conditional writes"](../../docs/adapter-surface.md#conditional-writes)).

- **The generation** is the wrapper's `g`, a random UUID every write sets
  (`attach`, `replaceIf`). It sits outside the ciphertext and the
  wrapper stays `v: 2`, so a replica that does not know `g` reads the record
  as before, and its own write leaves `g` out. Such a record is given a fresh
  `g` by its first versioned read, in the same script, its TTL kept; a
  conditional write against it answers `conflict` and mints nothing. A `g`
  that is no generation makes the record unreadable, like any other: `get`
  and `getVersioned` alike remove it and answer `null`.
- **The generation's shape is part of the record format.** A replica reads
  only a `g` that is a store generation (a string of 1 to 128 visible ASCII
  characters other than `"`). So a release that changed what `g` holds would,
  during a rolling upgrade, have the older replicas remove the records the
  newer ones write, and their users re-federate. Such a change ships in two
  steps: first a release whose readers accept both shapes, then the writer.
- **One script per record write and conditional member**, on the record's
  key, and for a write its replay key, on one Cluster slot: the attach
  (`attachRecord`), the versioned read (`readVersioned`), the replace
  (`replaceIfGeneration`) and the delete (`removeIfGeneration`). `missing`
  means no key, so a record past its `PX` is `missing` on Redis's own clock.
- **On a full server.** The delete's and the versioned read's scripts
  declare `allow-oom` (`#!lua flags=allow-oom`, Redis 7.0+), so a full
  `noeviction` server still runs them, and a record stays readable and
  removable when nothing more can be written. Besides the delete, the
  removal writes only its answer: one small replay key per call, living
  about 2 s, and on `missing` or `conflict` that key is all it writes. A
  versioned read of a record written without a generation is a write, the
  mint and its replay key, once per such record; it runs there because a stored token is served
  from the versioned read, and a conditional removal starts from it, so
  without it a full server would neither serve nor remove such a record
  until memory was freed. The attach and the replace are refused there.
  Every one of these scripts may write, so a read-only replica refuses each,
  the versioned read included: the primary answers it.
- **A versioned read never removes a record `get` reads.** It mints a
  generation into a record that decodes to a `v: 2` wrapper with no `g` and
  whose first byte is `{`, splicing `"g"` in after that byte rather than
  re-encoding the record. A record `get` reads but that the read can neither
  find a generation in nor mint one into makes `getVersioned` reject, as an
  outage would; only a record `get` cannot read either is removed.
- **The deadline.** `attach` and each conditional write carry a deadline
  the adapter sets at issue, its `Date.now()` plus the 1 s write timeout, in `ARGV`; the
  script compares it with `redis.call('TIME')` before it reads or writes
  anything, and at or after it writes nothing (`late`). The adapter stops
  waiting at the same timeout. Either way it rejects with an unknown
  outcome, never that nothing was written: a `late` answer says only that
  the copy that answered wrote nothing, and another copy of the same write
  may have committed, or may still commit within W. So the write lifetime W
  is 2 s: the 1 s write timeout plus the 1 s clock skew allowed between the
  app's and Redis's clocks (NTP; the operator runbook's "Replica clocks").
  An issued `attach` or conditional write commits or fails within W. That holds while
  the two clocks agree within the skew. The skew tolerance is one-sided: a
  Redis clock δ ahead of the app's shortens the usable window to the write
  timeout less δ, and at the full declared skew every conditional write is
  refused, `attach` included, an outage (it fails closed), never a wrong
  write. A late command
  — resent by the driver after a reconnect, queued while the connection was
  down, or held by a stalled server — writes nothing. The check bounds when
  a script starts, so one assumption stands beside it: the server does not
  stall inside a running script, between its clock check and its write, for
  the whole of W.
- **Replay.** `attach` and each conditional write therefore keep their
  answer under a replay key of its own (`${keyPrefix}w:{<tag>}:<id>`, in the key table
  above, on the record's Cluster slot) until the declared clock skew past
  its deadline: a copy that reaches the server before then answers what the
  first copy answered and writes nothing, so it does not answer `conflict`
  or `missing` for a write that landed, even when another server, whose
  clock may lag by the skew, judges the copy after a failover or a slot
  migration; one that reaches it later is `late`, though another copy may
  have committed, or may still commit within W on a server whose clock lags
  by the skew. `attach` overwrites whatever the record holds, so without
  this a resent copy would put an older record and its generation back over
  a later write.
- **The mint is bounded the same way.** A versioned read that mints carries
  the same deadline and keeps that it minted under a replay key of its own,
  keyed by the generation it mints, until the clock skew past the deadline.
  A copy of that read the driver sends again, or one that reaches the server
  at or after its deadline, mints nothing: it answers a record that carries a
  generation as any read does, and makes `getVersioned` reject, as an outage
  would, on a record that carries none. So a resent read never puts the
  generation another reader already holds onto a record an older replica
  wrote since, and that reader's conditional write answers `conflict`.
- **The index.** A copy of `attach` the driver resends after a logout
  writes no record, but its index add (one MULTI before the script) lands
  again: the session's `idx:` set is made again, naming a record that is
  gone, until the store TTL. That is harmless: a later `removeBySid` unlinks
  the missing key and the set. A conditional write never removes an index member, and
  `missing` and `conflict` never add one. `replaceIf` raises the index's TTL
  before its script (`pExpireGT`, which adds no member and makes no key), and
  after `updated` re-adds the member with `sAddWithTtl`, so the index's
  deadline is no earlier than the record's and an index that had expired is
  made again. A member that names a removed record is harmless: `removeBySid`
  unlinks a missing key.
- **No rollback.** This store assumes acknowledged writes are not rolled back
  (persistence, plus a failover setup that keeps acknowledged writes). A
  deployment that accepts acknowledged-write loss on failover also accepts
  that a conditional write may see a restored, older generation.
- **No eviction.** The replay guarantee assumes `maxmemory-policy
  noeviction`. A replay key carries a TTL of about 2 s, so a `volatile-*` or
  `allkeys-*` policy may evict it first, and a copy the driver resends within
  W then writes again: an `attach` puts an older record back over a later
  write, or a logged-out session's tokens back (`replaceIf` and `removeIf`
  still meet their generation check). The module reads the policy once at
  boot (`INFO memory`, then `CONFIG GET maxmemory-policy`). A `volatile-*`
  or `allkeys-*` policy refuses the boot with a `RedisStoreEvictableError`
  (`reason` `federation-token-store-evictable`, `maxmemoryPolicy`), the
  `cause` of a `provides-factory-failed` BootError. A policy it could not
  read (a managed server that blocks both questions, or no answer at boot)
  or does not know is one info line,
  `federation_token_store_eviction_unchecked` (`store`, `adapter`;
  `maxmemoryPolicy` for one it does not know; `err` when the server refused
  the question or could not answer), and the boot goes on. A store built
  with `createRedisFederationTokenStore` or the builder is not checked.

A `FederationTokenStoreClient` of your own implements the five primitives
`attach` and the conditional members use: `attachRecord`, `readVersioned`,
`replaceIfGeneration`, `removeIfGeneration` (each one atomic step, refusing
at or after the deadline they are handed, `readVersioned` only its mint, and
keeping their answer, or `readVersioned` its mint, under the replay key they
are handed until the clock skew they are handed past it) and `pExpireGT`; and `durability`, the
server's report the module's boot check reads. The builder refuses a client
without them. [`federation-tokens.conditional.test.mts`](__tests__/federation-tokens.conditional.test.mts)
runs `federationTokenStoreConditionalContract` (`@o3co/auth-provider-test-kit`)
over the store on two connections.

## Federation grants

Their own keyspace, because what they hold outlives every session: default
prefix `fg:` (`redis-federation-grant-store.keyPrefix`).

| Key | Type | Holds |
| --- | --- | --- |
| `fg:{<id>}:grant` | **hash** | the non-secret record: status, version, the authorization as one canonical text, the current intent, the rotation budget |
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
is judged by Redis. The scripts guard on arithmetic copies of the expiry and
the upstream account kept beside the canonical text; a write that has the
record in hand refuses when the copies no longer agree with the text, and a
revocation, which gates on none and must always win, takes the horizon it
honours from the text itself (#627) — read as the TypeScript reader reads it,
so a value the reader refuses gives no horizon and the revocation proceeds —
and a copy moved into the past cannot keep a live grant from being ended.

The port's `takeRotation` is one script over two fields of the
grant hash, `rotationsSince` and `rotationsCount`: non-secret, outside the
envelope, compared against the version and written with the version bumped
once, in the same step, so the grant it answers carries the new one. Its
`refundRotation` is one script too: at the version the take left,
and only for the window whose `rotationsSince` it names, it counts
`rotationsCount` down by one, never below 0, and bumps the version, so a
second give-back of the same attempt is refused. Both read the caller's
clock, as every write does. `replaceCredentials` and every other write keep
the fields; `activate` removes both. A record without both, or with one that
is not a whole number (or a count below 0), has no window, and the scripts
and the reader agree on that; a window counted down to 0 is still one, and
the next take counts into it. A `FederationGrantStoreClient` of your own
implements both primitives, `takeRotation` and `refundRotation`: they are
required members of the client. During a rolling deploy, an activation by an earlier
release leaves the fields in place, so a renewed grant can start with the
budget it had.

The port's take is a version fence: it bumps the version, and every later
write of the attempt, its give-back included, is guarded by the version of the
grant it answered, so a late give-back of an earlier attempt can never refuse
the next holder's write. This store's take bumps, so the fence holds here.
Anything that reads a grant's `version` from Redis directly sees it move on
every take. Core and this package ship in lockstep, and the peer range a
release publishes (`^` the release's own version) names the core that reads
the guard off the grant the take answered; no released core takes a rotation
without it. Keep the two at the same release: a core older than the fence
would keep the version it read before the take, and every write after the
take would be refused.

Every script that bumps the version reads it as the TypeScript reader does: a
safe integer whose successor is one too. A version stored at
`Number.MAX_SAFE_INTEGER`, or one that only Lua's `tonumber` reads (`2.0`,
`0x2`), is refused by every write that bumps, which writes nothing, and is
compared as no version at all. A take also refuses one below
`Number.MAX_SAFE_INTEGER`: the version it answers guards the attempt's next
write, which must be able to bump it. A revocation, which must always win,
still ends such a grant and leaves its version as it was. Over a version only
`tonumber` reads, that leaves a revoked record the reader cannot decode; the
scripts only ever write canonical versions, so only a write to the keyspace
from outside this store produces one.

The credential is sealed under a key **ring**, in core's `v2` key-ring
envelope (`sealWithKeyRing`, with this store's purpose `o3co:redis:v2`): the
first key seals, every configured key opens, and the envelope names the one
that sealed it, so a key can be introduced without re-sealing grants that are
paused. A key that is not in the ring reads as `key_unavailable` — a
configuration problem an operator undoes by putting it back — and is told
apart from a credential that will never open again. Nothing is ever deleted
on a read. Rotate by adding the new key last, then moving it first, and keep
the old one listed for 365 days after the last replica that sealed with it
stopped — the procedure, and why it is the ceiling and not `maxExpiresIn`, is
in the [operator runbook](../../docs/operator-runbook.md).

**The credential is strict; what it cannot hold goes into its extension.** The
credential's tuple, authenticated data and `format` stay what every earlier
release reads. Facts it cannot hold without breaking those readers — first the
access token's `effectiveExpiresAt` — go into the grant hash's `ext` field: a
JSON object of named keys, sealed under the same key ring, in its own
envelope, under its own label, the credential's whole binding and the SHA-256
of the exact credential
envelope written with it (under `allow-plaintext`, that digest is carried as
`bind`). The script that writes the credential writes or removes `ext` in the
same step, so a rewrite of the credential by any release orphans the `ext`
beside it — except, under `allow-plaintext`, where a credential's spelling is
deterministic, a byte-identical rewrite by a release that does not know `ext`:
the same token, which keeps its end. An `ext` that is absent, too long, does not open beside its
credential or does not parse reads as absent, and the credential reads as it
would without it. Unknown keys are ignored on read and dropped on every
rewrite, so every key must be safe to lose: an absent `effectiveExpiresAt`
ends the token at the released end (`obtainedAt + issuedLifetime`).

**Acquisition's records sit beside the grants.** The intent store keeps the
intent a backend lodged, the consent challenge and the connect transaction
under `<prefix>{intents}:…`, where the prefix is its own section's,
`redis-federation-grant-intent-store.keyPrefix` (default `fg:`, the grant
store's default) — a deployment that moves the grant store's namespace sets
this one to the same value; the standalone template refuses to boot with the
grant store's moved and this one left at its default. It is its own module so that grants can live in
Redis while acquisition stays in memory on a single replica (a restart then
loses flows in progress and nothing else); nothing spans the two keyspaces.

## Device authorizations share one slot

`redisDeviceCodeStoreModule` (#433) keeps a pending RFC 8628 authorization
as two keys:

| Key | Type | Holds |
| --- | --- | --- |
| `${keyPrefix}{devauth}:code:${device_code}` | hash | the record — status, expiry, interval, scope, subject, the approval's instant (`approvedAtMs`), and the approving session's `amr` (a JSON array) and authentication instant (`authTimeMs`) when the approval was handed them. The approving script writes them in the same `HSET` as the approval; one it was not handed is not written. |
| `${keyPrefix}{devauth}:user:${user_code}` | string | the `device_code` it belongs to |

`keyPrefix` is `redis-device-code-store.keyPrefix` (default `devauth:`); the
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

*Rolling upgrade.* A record approved before an upgrade, or by a replica that
has not been upgraded yet, holds none of the fields that release did not
write, and reads each as absent. An older replica that polls an approval a
newer one wrote ignores the fields it does not know. So does a stored `amr` that is not a non-empty JSON
list of non-empty strings, or an `authTimeMs` that is not the whole epoch
milliseconds of an instant at or after the epoch. Nothing needs migrating.

## Consent records and parked requests

`redisConsentStoreModule` (#561) provides both slots the consent step needs —
one switch, as core's memory module is, because `createOAuthRouter` refuses a
composition with one and not the other. Its keys:

| Key | Type | Holds |
| --- | --- | --- |
| `${keyPrefix}rec:${len}:${sub}\|${len}:${clientId}` | hash | a consent record — `scopes` (JSON array), `grantedAt`, `expiresAt` when it has one |
| `${keyPrefix}{pending}:ch:${challenge}` | hash | a parked `/authorize` request, its `sessionId` and `expiresAt` |
| `${keyPrefix}{pending}:sess:${sessionId}` | sorted set | that session's challenges, scored by the order they were parked |

`keyPrefix` is `redis-consent-store.keyPrefix` (default `consent:`). A consent
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

## MFA stores

`redisMfaFactorStoreModule` and `redisMfaTransactionStoreModule` (the MFA
ADR's D7, D8, D10, D12, D21, D25) are two modules, each with its own client
slot and prefix, so a deployment can put the factors on a Redis of their own.

| Key | Type | Holds |
| --- | --- | --- |
| `mfaf:{<subject>}` | hash | one field per enrolled factor (its id): `<version>\n<fixed JSON>\n<mutable JSON>`; and `~g`, the set's generation. No TTL while it holds a factor; holding `~g` alone, it is the emptied set's tombstone, expiring 24 hours after its last membership write |
| `mfaf:{<subject>}:w:<generation>` | string | one membership write's answer, kept until the declared clock skew (1 second) past the write's deadline (about two seconds in all) |
| `mfat:tx:{<id>}` | hash | one MFA transaction, expiring at its `expiresAtMs` |
| `mfat:binding:{<digest>}` | sorted set | one binding's transactions, at most `MFA_MAX_TRANSACTIONS_PER_BINDING` (5): one member `<incarnation>:<id>` each, scored by its `expiresAtMs`, the key expiring at the latest; `<digest>` is the SHA-256 of the binding, so no key holds the express session id |
| `mfat:lock:{<subject>}` | hash | D21's consecutive run, the reservations in flight, and whether a hold's first refusal was answered (`held`) |
| `mfat:week:{<subject>}` | sorted set | the weekly window: one member per failure, scored by its time |
| `mfat:recovery:{<subject>}` | hash | the subject's generation (`g`), its recovery-set floor (`floor`), and one field per recovery authorization, `a:<operation>:<sid>` |
| `mfat:lease:{<subject>}` | string | the token of the subject's lease holder, expiring at the lease's end |
| `mfat:proof:{<subject>}` | string | the email proof an operator reset requires at the next first binding |
| `mfat:session-proof:{<subject>}:<sid>` | string | the account-email proof given in one session, JSON `{provedAtMs, untilMs}`, expiring at `untilMs` |
| `mfat:first-binding:{<subject>}` | string | the subject's first-binding mark, JSON `{atMs, untilMs}`, expiring at `untilMs` |

Subjects and ids are base64url of their JSON, as the federation grant store
spells its ids, so no brace moves a hash tag and no two values share a key.
Neither prefix may contain a brace. A subject's factors are one key; a
subject's lock hash, week, recovery hash and lease share the subject's tag,
so each of D21's operations, and each recovery and lease operation, is one
script on one Cluster slot.

**The factors.** Every membership write is one script (below); `update` is
one script that compares the version as text and carries the fixed part over
byte for byte — it never decodes the JSON, since `cjson` writes an empty
array back as `{}` — and answers `null` to a value that is not exactly three
lines, never cutting one it did not write down to a record it did. A stored
record the adapter cannot read back refuses the subject's whole list: never
"no factor", which would open a first binding. So `createIf` and
`update` refuse with a `RangeError`, before anything is written, whatever a read would
refuse — a binding outside D24's three, a field that is not the type the
record declares, a date that is not a whole instant within the Date range
(±8.64e15 ms; a stored one past it would read back as an Invalid Date, a
fraction as another instant), and, for `update`, a record
at `Number.MAX_SAFE_INTEGER`, whose next version would be no safe integer
(core's `checkMfaVersionAdvances`, which the transactions' `update` applies
too).

**The factor set's generation.** A subject's factors are one set with a store generation, under the set rules
of core's conditional-write convention
([docs/adapter-surface.md, "Conditional writes"](../../docs/adapter-surface.md#conditional-writes)).

- **Where it is kept.** The subject's hash holds the set's generation under
  the reserved field `~g`, beside the factor fields; `~` is not base64url, so
  no factor's field is `~g`. The adapter mints each generation with core's
  `newStoreGeneration` and hands it to the script; a copy of the write the
  driver sends again finds the write's replay key and writes nothing (see
  "The deadline"), so none is issued twice (rule 8). `list` and
  `listVersioned` never answer `~g` as a record.
- **One script per step** (rules 1, 2 and 4). `listVersioned` answers the
  factors and `~g` from one snapshot, and `null` for no key. `createIf` and
  `removeIf` compare `~g` and write in the same script; `removeIf` checks the
  generation before the factor. `removeAllForSubject`, the operator reset and
  account deletion, is one script serialised with them: it deletes the
  factors and leaves `~g` at a new generation, making the key when there was
  none. `update` keeps `~g`.
- **The primary, never a replica** (rule 2). `listVersioned` and every
  membership write are scripts that start with `#!lua` and no `no-writes`
  flag, which Redis 7.0 and later refuses on a read-only replica (`READONLY`).
  That holds for a replica with `replica-read-only yes`, Redis's default; a
  replica configured writable would run them. The versioned read therefore
  always reflects every write acknowledged before it began. `list`, the plain
  read, stays a plain `HGETALL` and carries no such guarantee: a write decided
  on what it answered is not fenced by the set's generation.
- **The tombstone** (rule 6). A write that leaves the hash holding `~g`
  alone — the last factor's removal, or a reset, of an already empty set
  too — sets the key to expire `BUNDLED_STORE_WRITE_LIFETIME_MS`, 24 hours,
  later, starting that retention again at each such write; a write that
  leaves a factor in it takes the expiry off, so a set holding a factor never
  expires. An emptied set reads as one never written only once 24 hours have
  passed since its last membership write. A `volatile-*` eviction policy may
  evict a tombstone sooner: the module warns
  (`mfa_factor_store_tombstone_evictable`). Run `noeviction`.
- **A hash with factors and no `~g`** was written by a development build from
  before the set had a generation (the store was never released, so nothing
  needs migrating). Every conditional write against it answers `conflict` and
  mints nothing; its first `listVersioned` gives it a fresh generation in the
  same step, keeping its expiry (rule 8).
- **The deadline.** Each membership write carries a deadline the adapter sets
  at issue, on the app's clock: `Date.now()` plus the write timeout, 1 000 ms.
  The script compares it with the server's clock (`TIME`) before it reads or
  writes anything; at or past it, the script writes nothing and answers `late`,
  which the adapter rejects as an outage. The adapter waits for the answer no
  longer than the write timeout. Either rejection, `late` or the wait ending,
  means the outcome is unknown, never that nothing was written: a `late`
  copy wrote nothing, but another copy may have committed, or may still
  commit within W (below). The deadline stays inside the
  adapter: nothing crosses the port.
- **A copy sent again.** ioredis sends again a command whose reply a dropped
  connection lost, and the first copy may have run. Each membership write
  therefore keeps its answer under a replay key of its own
  (`<key>:w:<generation>`, on the subject's hash tag) until the declared
  clock skew past its deadline: a copy that reaches the server before then
  answers what the first copy answered and writes nothing, so it neither
  writes a generation back over a later one nor answers `conflict` for a
  write that landed, even when another server, whose clock may lag by the
  skew, judges the copy after a failover or a slot migration; one that
  reaches it later is `late`, though another copy may have committed, or may
  still commit within W on a server whose clock lags by the skew. A
  `volatile-*` policy may evict a replay key
  early; the module's warning names it.
- **A full server.** Under `noeviction`, Redis refuses a script that does
  not declare `allow-oom` once `maxmemory` is reached. The removal
  (`removeIf`), the reset (`removeAllForSubject`) and
  `listVersioned` declare it: each writes only `~g`, the replay key and an
  expiry, so a factor stays removable, an attacker's among them, and the
  operator reset still runs on a full server. The create (`createIf`)
  declares no flag and is refused there (`OOM`), an outage.
- **The write lifetime W** (rule 6). W is 2 000 ms
  (`REDIS_MFA_FACTOR_STORE_WRITE_LIFETIME_MS`): the write timeout, 1 000 ms,
  the same as the `commandTimeout` this README asks of the connection and the
  least `mfa.storeTimeoutMs`; plus the clock skew allowed between the app's
  and Redis's clocks, 1 000 ms, the operator runbook's rule that every
  replica's and Redis server's clock agrees within 1 second (NTP). An issued
  membership write commits or fails within W.
- **The assumption W rests on.** Half 2 of the bound holds while the app's
  and Redis's clocks agree within the declared skew. A late command, whether
  resent after a reconnect, queued while the connection was down, or held by
  a stalled server, writes nothing. The check bounds when a script starts,
  so one assumption stands beside it: the server does not stall inside a
  running script, between its clock check and its write, for the whole of
  W. A Redis clock ahead of the app's shortens the time a write has to reach
  the server by its lead, and a write that misses it is refused: an outage,
  never a write past W.
- **Acknowledged writes** (rule 8). The adapter's assumption: this store
  assumes acknowledged writes are not rolled back (persistence plus a
  failover setup that keeps acked writes); a deployment that accepts
  acked-write loss on failover also accepts that a conditional write may see
  a restored older generation. What that asks of an MFA deployment:
  acknowledged factor-set writes are not rolled back (no async-replica
  failover without `WAIT`, or the operator accepts that a failover may
  restore removed factors).

**The transactions.** Every operation the port calls atomic is one script:
insert-only `create`; `update`, a compare-and-set on the version and on the
incarnation `create` wrote, after core's own checks of the patch; and
`reserveAttempt`, `takeChallenge` and `consume`. A record is kept as core's
`newMfaTransactionRecord` answers it and read back through the same function,
so it has the in-process store's shape; one that does not read back is
answered as absent, and the ceremony starts again. So is one at or past its
`expiresAtMs` on the store's own clock (`now`, `Date.now` by default), by every
operation — `reserveAttempt` and `takeChallenge` in their scripts, which are
handed that clock, read the deadline from a hash field of its own (never
decoding the record, which `cjson` reads more narrowly than `JSON.parse`), and
spend or take nothing then: the key expires on the
server's clock, and a server running behind must not let a ceremony spend an
attempt, take a challenge or complete past its deadline. The record travels as JSON,
as the session envelope's `claims` and the cookie session's `user` do, so a
login continuation's `user` and `claims` must be JSON-representable: a `Date`
comes back as its string and an `undefined` value as a missing key, where the
in-process store's `structuredClone` keeps both.

**A binding's transactions.** A binding — a browser session — holds at most
`MFA_MAX_TRANSACTIONS_PER_BINDING` (5) live transactions, and one more ends
the one of them that expires first, as core's port says. Its index is the
`mfat:binding:` sorted set, which shares no hash tag with the transactions:
the adapter holds the cap's policy and the client three one-script
primitives (`indexTransaction`, `unindexTransaction`, `evictTransaction`).
`create` writes the transaction, then one script adds its member and takes
out those that expire soonest past the cap — never the new one — and
the adapter deletes each taken out through a script that compares its
`incarnation`, so a member left behind never ends a transaction created again
under its id, for this binding or another. `consume`, and a reservation past
`max`, take the member out. The key expires at the latest deadline it holds,
set again whenever a member is added or removed.
These are separate steps, not one atomic one: while creates for one session
are in flight it may hold more than five; only a step that failed leaves an
excess, until it expires. A create refused at its index step has already
written its transaction. An eviction that fails is warned
(`mfa_transaction_evict_failed`) and the create still answers; a member that
cannot leave is warned (`mfa_transaction_unindex_failed`) and counts toward the
cap until it is taken out: while live members expire sooner, a later create
ends one of them first, so a live one may go early; once its transaction's
expiry has passed, it goes first.
The bound is the store managing the state the Provider owns; abuse and DoS
defence stay outside the Provider, and the login path is bounded by the login
limiter and a correct password, not by this cap.

**The subject lock.** `reserveSubjectAttempt`, `settleSubjectAttempt` and
`noteExemptSuccess` are one script each that applies the port's rules exactly
as core's in-process store does — the same replay of the run for the backoff,
the same count of the week — judged on the time the
caller passes; [`mfa-transaction-store.test.mts`](__tests__/mfa-transaction-store.test.mts)
holds the two stores to the same answers over random walks of the
operations. What a script forgets, and what Redis reclaims, is judged no
later than the server's clock less a day. The hard hold is the lock hash's
`hard` field, the time it was fixed: the reserve or exempt script that finds
the run — reservations in flight counted — at the `hardLimit` it is handed
writes it (`HSETNX`) in the same step, the reservation that reaches it being
let through; from then every reservation is refused `hard` whatever
`hardLimit` it is handed, the exempt script ends nothing, and a settle
lifts nothing; only an applied recovery removes it. While a run is counted
or the hold stands the keys carry no TTL — only a success, an exempt
success before the hold, or an applied recovery ends a run — and once
neither is they expire a day after the last failure stops counting. A
`hard` field the scripts cannot read refuses every lock operation, as any
other field does. A missing or non-numeric `hardLimit` argument is refused
before anything is read. The field holds the later of the fixing script's
`now` and the run's newest attempt. A refusal on a held subject whose lock
hash carries a deadline takes it off (one `PTTL` read; a write only then).
v0.16.0 ships no subject-lock scripts; between pre-release builds, a
replica of one that does not write `hard` neither reads nor keeps it: its
exempt script can end a run at the limit, its reserve script lets attempts
through below the limit, and its `keep()`, finding no run and no week, can
delete both keys, the field with them. Drain the old replicas before
relying on the hard hold.
A refusal answers whether it is the first since an attempt was
let through (`first`) from the lock hash's `held` field, which the first
refusal of a hold writes and an attempt let through deletes, so a subject
refused again and again costs no write after the first. A state a script
cannot read refuses the attempt; it is never read as a state that holds
nothing. A lock-hash field of a kind the scripts
do not read (`t:<digest>` among them) is ignored and goes with the keys, and
a transaction hash's `sends` and `lastSentAtMs`, where present, are not read:
neither loosens a limit the store keeps. The email-proof requirement is a key of
its own with no TTL: an applied recovery leaves it, and consuming it is one
`DEL`.

**Recovery, the generation, the lease and the floor.** `authorizeSubjectRecovery`
and `applySubjectRecovery` are one script each. An authorization is a field of
the subject's recovery hash, `p|<expiresAtMs>|<recoveryId>` while pending and
`a|<generation>|<expiresAtMs>|<recoveryId>` once applied, ending on the server's
clock; the authorize script refuses an end not after that clock or further
ahead than an hour and the skew, and drops the authorizations ended on it. The
apply script runs over the lock hash, the week, the recovery hash and the
lease: it checks the lease's token, then the authorization, then judges the
lock state exactly as core's in-process store does, and moves the generation
(computed before the first write, set with `HSET g`) in the same step; a reset deletes the lock and week keys unread,
so it ends a lock state the other scripts cannot read. Every reply of the apply
script ends with the hard hold as it stands after the call: `1` and from when a
rebind counts — the `hard` field's time plus the skew, floored to whole
milliseconds, as decimal text, the same bound the script lifts the hold by — or
`0` and an empty string. A `hard` field the script cannot read, or whose bound
is not a safe whole number from 0, is an outage raised before the script's first
write, a refused reset's answer included; an applied reset still deletes it
unread. A
`MfaTransactionStoreClient` of your own whose `applySubjectRecovery` answers
the shorter reply, without that last element, is refused as an outage: answer
as `ApplyMfaSubjectRecoveryReply` says. The acquire script
compares the generation a writer captured with `g` (absent is `0`) and writes
the lease with `SET NX PX`; the release is a compare-and-delete of its own,
which answers a lease at its last millisecond (`PTTL` 0) as lapsed, `false`,
and one holding the token with no deadline (`PTTL` -1) as an outage; an apply
and a floor raise take neither as held. The
floor is the recovery hash's `floor` — a recovery-code set's generation, not
the subject's — raised under the lease by one script that never lowers it.
Counts are safe whole numbers (at most 2^53−1) and an authorization's end lies
within the Date range; anything else is an outage. The recovery hash carries no TTL once it
holds a generation or a floor — losing the generation refuses a writer that
captured it and lets through one that captured 0 before a recovery, losing
the floor brings an older recovery-code set back — and before that expires a
day after its latest authorization ends. Every script reads and validates the
whole recovery hash, and an apply the lock state too, before its first write,
and holds counts to canonical decimal text, compared as numbers. A generation,
floor or authorization the store cannot read is an outage, with nothing
written, never none, and so is a lease key with no deadline. The lease is logical: a write that outlives
it is told so at its release (`false`), never stopped. Evicting a lease lets a
second writer at the subject's factor set, so the MFA stores require
`noeviction`; the recovery hash, with no TTL once it holds a generation or a
floor, is never picked by a `volatile-*` policy, and `allkeys-*` is refused at
boot.

**A session's account-email proof.** One string per session of a subject,
written with one `SET … PX`, whose lifetime is `untilMs` less the store's own
clock (`now`), so a later proof for the session replaces the earlier one and
its end. A read answers it absent at or past `untilMs` on that clock or at the
time asked about, and absent when it does not read back as a proof: losing
one fails closed, and the user proves again. The factor store's durability
check does not cover it.

**A subject's first-binding mark.** One string per subject, judged on one
clock, the server's (`TIME` in its two scripts): its end, which mark a note
keeps and the key's deadline. The note script refuses a mark whose end is
not after that clock, or whose time lies further from it than
`DEFAULT_CLOCK_SKEW_MS`, and otherwise keeps the later time and the later end
of the mark held and the one noted — as core's `laterFirstBindingMark` —
written with `PXAT` at that end. A held mark is judged on its shape alone
(whole times, an end after its time by at most a day,
`MFA_CLOCK_SKEW_ALLOWANCE_MS`), never on where its time sits on the server's
clock, so a clock stepped back never lets a note move a mark back; a held
value without that shape, or a key of another type, gives way to the note.
The read script answers the value and the server's clock in one step, and the
read answers the mark absent only once that clock passes its end: this side's
clock (`now`) decides nothing about a mark. A value that does not read back as
a mark — a field beyond `atMs` and `untilMs` included, which a note never
writes — whatever its end looks like, or a key of another type, is an outage,
never absent, since an absent mark trusts the session it is there to distrust.
Where a sound mark's time sits on the caller's clock is the caller's reading
to judge (`readFirstBindingAt`). The mark's guarantee rests on the login
replicas' clocks agreeing within `DEFAULT_CLOCK_SKEW_MS`: they date the
sessions it is compared with, and the note's time. The module's durability
check covers it as it covers the email-proof requirement; a `volatile-*`
policy may evict it, which fails open.

**Durability at boot (D12).** Before providing its store each module asks the
server, through its client's `durability()`, each part on its own: the policy
from `INFO memory` — `CONFIG GET maxmemory-policy` only where INFO does not
say, so a managed server that blocks `CONFIG` is still held to the refusal —
AOF from `INFO persistence`, and `CONFIG GET save` only when AOF is off, to
tell RDB snapshots from none. The policy is judged by an allow-list:
`allkeys-lru`, `-lfu` and `-random` refuse the boot
(`mfa-factor-store-evictable`, `mfa-transaction-store-evictable`) whatever
else could not be read; `noeviction` passes; the four `volatile-*` policies
are one warning from each store, with `evictableFamilies`: from the factor
store (`mfa_factor_store_tombstone_evictable`), whose emptied sets'
tombstones carry a TTL, and an evicted one reads as a set never written
before its 24 hours are up, and whose writes' replay keys carry one until
the write's deadline, and an evicted one lets a resent copy apply again; from the transaction store
(`mfa_transaction_store_lock_evictable`), whose lock and week keys carry a
TTL once no run is counted, and an evicted one lifts a D21 hold early; a first-binding mark
always carries one, and an evicted mark fails open; a lease always carries
one, and an evicted lease lets a second writer in. RDB snapshots without AOF (`mfa_factor_store_lossy`,
`mfa_transaction_store_lossy`) and no persistence (`…_volatile`) are each one
warning. A part that could not be read — a question the server refused
(`NOPERM`, an unknown or renamed command, a disabled one), or answered without
the value — and a policy the allow-list does not know are named in one
warning that the check could not run (`…_durability_unchecked`: `unread`,
`maxmemoryPolicy`), and the boot goes on; any other reply error, and a server
that cannot be reached, fails it. The transaction store runs the check
because of the email-proof requirement (D12's step-3 amendment). `noeviction`
is what both stores' key families are meant to run on.

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
`MfaFactorStore`'s suite is not copied: it is the test kit's published
`mfaFactorStoreContract` and `mfaFactorStoreConditionalContract`
(`@o3co/auth-provider-test-kit`, a devDependency; the latter runs the generic
conditional-set suite and the factor set's own cases), which
[`mfa-factor-store.test.mts`](__tests__/mfa-factor-store.test.mts) runs over
two connections, with a tombstone's expiry brought forward by `PEXPIRE`.
`AttemptCounter`'s suite is the test kit's `attemptCounterContract`, which
[`attempt-counter.test.mts`](__tests__/attempt-counter.test.mts) runs over two
connections, on a hand-moved clock and on the real one.
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
  AES-256-GCM sealing (the federation-token store's `v1` envelope, and the
  federation grant store's purpose label over core's `v2` key-ring envelope,
  which lives in core's `sealing/` leaf), the plaintext guard both sealing
  stores share (one escape hatch, `FEDERATION_TOKENS_ALLOW_INSECURE=1`, for
  both), the federation-grant codecs and lock, the MFA stores' key spelling and
  their boot durability check, and the three sid-keyed structures (HASH, ZSET,
  SET) the session and federation adapters are built from — same
  `${keyPrefix}${sid}` layout and TTL contract, different Redis type.
