/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ---------------------------------------------------------------------------
// Backing client contracts for Redis adapters in this package.
//
// These interfaces describe the methods the adapters consume, expressed in
// Redis protocol terms (`hSet`, `zAdd`, `pttl`, `multi`/`watch`/`exec`, etc.).
// They live in `@o3co/auth-provider-redis` rather than in core because the
// shape is intrinsically Redis-flavoured: a consumer wiring a non-Redis
// backend (DynamoDB, Postgres, etcd, ...) writes their own contracts and
// adapters, not implementations of these.
//
// Each interface ships with a `declare module "@o3co/auth-provider-core"`
// augmentation that adds the matching backing-client slot to ComponentMap,
// so consumers wiring redis backends via `bootstrapComponents` get the slot
// types whenever they import from this package.
//
// Per Phase 10 addendum §3 (the "backing client interface" pattern: narrow
// per-purpose Redis-command contracts owned by the adapter package) +
// v0.5.0 pre-tag interface review S3 (the decision that core does not
// declare them). Both resolve in docs/design-campaign-index.md.
// ---------------------------------------------------------------------------

// --- ChallengeStoreClient --------------------------------------------------

/**
 * Backing client for ChallengeStore adapters. Adapter implementations
 * (e.g. `createRedisChallengeStore`) consume exactly these methods.
 */
export interface ChallengeStoreClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	pttl(key: string): Promise<number>;
	del(key: string): Promise<number>;
}

// --- AccessTokenDenylistClient ---------------------------------------------

/**
 * Backing client for AccessTokenDenylist adapters (#277). Adapter
 * implementations (`createRedisAccessTokenDenylist`) consume exactly these
 * methods.
 *
 * `set` is the plain PX form with no `NX`: re-revoking a jti is idempotent and
 * last-write-wins on the expiry, matching the memory adapter. That is also why
 * this is a separate interface from {@link ReplaySeenSetClient}, whose whole
 * contract turns on the `NX` return value.
 */
export interface AccessTokenDenylistClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	exists(key: string): Promise<number>;
}

// --- ReplaySeenSetClient ---------------------------------------------------

/**
 * Backing client for ReplaySeenSet adapters. Adapter implementations
 * (e.g. `createRedisReplaySeenSet`) consume exactly these methods.
 */
export interface ReplaySeenSetClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	exists(key: string): Promise<number>;
}

// --- RefreshTokenFamilyClient ----------------------------------------------

/**
 * Chainable transaction pipeline returned by `RefreshTokenFamilyClient.multi()`.
 */
export interface RefreshTokenFamilyMultiClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): RefreshTokenFamilyMultiClient;
	/**
	 * Execute the queued commands.
	 *
	 * **MUST reject when any queued command failed.** A driver that reports
	 * per-command errors inside the reply — ioredis resolves with one
	 * `[error, result]` tuple per command and does not reject, because `EXEC`
	 * itself succeeded — has to be adapted here, or a refused write is handed
	 * to the caller as a success. The pipelines in this package pair a mutation
	 * with the expiry that bounds it, so a swallowed failure is a key stranded
	 * with no TTL: the shape #269 already paid for once.
	 *
	 * Resolving with `null` is **not** a failure: it is the WATCH-abort signal,
	 * which the refresh-token-family CAS loop reads as "conflict, retry".
	 */
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for RefreshTokenFamilyStore adapters. The `duplicate()` method
 * returns a `DisposableRefreshTokenFamilyClient` bound to a new underlying
 * connection, required for WATCH/MULTI/EXEC CAS isolation per A3 §7.2.
 */
export interface RefreshTokenFamilyClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	get(key: string): Promise<string | null>;
	pttl(key: string): Promise<number>;
	watch(...keys: string[]): Promise<"OK">;
	unwatch(): Promise<"OK">;
	multi(): RefreshTokenFamilyMultiClient;
	duplicate(): DisposableRefreshTokenFamilyClient;
}

/**
 * A `RefreshTokenFamilyClient` that owns a single network connection and is
 * responsible for closing it. Returned by `RefreshTokenFamilyClient.duplicate()`
 * so consumer code can use `await using conn = client.duplicate()` for scoped,
 * exception-safe connection lifetime.
 */
export interface DisposableRefreshTokenFamilyClient
	extends RefreshTokenFamilyClient,
		AsyncDisposable {
	[Symbol.asyncDispose](): Promise<void>;
}

// --- UserSessionStoreClient ------------------------------------------------

/**
 * Backing client for UserSessionStore adapters. Declares only `set`, `get`,
 * `del` — the exact methods `createRedisUserSessionStore` consumes.
 *
 * `set` has two overloads:
 *  - plain PX form (no condition): always succeeds with `"OK"` per Redis
 *    `SET key value PX ms` protocol; never returns null.
 *  - PX+NX form: atomic insert-only, used by `create`; mirrors
 *    ChallengeStore.issue and RefreshTokenFamilyStore.registerFamily.
 *    Returns `"OK"` on insert, `null` when the key already existed.
 */
export interface UserSessionStoreClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	get(key: string): Promise<string | null>;
	del(key: string): Promise<number>;
}

// --- SessionRPRegistryClient -----------------------------------------------

/**
 * Chainable transaction pipeline returned by `SessionRPRegistryClient.multi()`.
 */
export interface SessionRPRegistryMultiClient {
	hSet(key: string, field: string, value: string): SessionRPRegistryMultiClient;
	pExpireAt(key: string, msTimestamp: number): SessionRPRegistryMultiClient;
	/**
	 * Safely set the key's expiry under concurrent writes (D-10 / CR-3).
	 *
	 * Effective semantics:
	 *   - If the key has no TTL, set it to `msTimestamp` (first-write case).
	 *   - If the key has a TTL ≥ `msTimestamp`, leave it unchanged
	 *     (truncation prevented under stale-`expiresAt` races).
	 *   - If the key has a TTL < `msTimestamp`, raise it to `msTimestamp`
	 *     (legitimate extension allowed).
	 *
	 * Implemented as a `PEXPIREAT … NX` + `PEXPIREAT … GT` pair (Redis 7.0+
	 * flags). A bare `PEXPIREAT … GT` is insufficient: Redis treats a
	 * non-volatile key as having infinite TTL for `GT`, so the GT clause
	 * silently no-ops on first write. The NX clause covers that bootstrap
	 * gap; the GT clause provides the truncation guard once a TTL exists.
	 *
	 * Requires Redis 7.0+. v0.5.1 pins the floor to Redis 7.2 LTS.
	 */
	pExpireGT(key: string, msTimestamp: number): SessionRPRegistryMultiClient;
	/**
	 * Execute the queued commands.
	 *
	 * **MUST reject when any queued command failed.** A driver that reports
	 * per-command errors inside the reply — ioredis resolves with one
	 * `[error, result]` tuple per command and does not reject, because `EXEC`
	 * itself succeeded — has to be adapted here, or a refused write is handed
	 * to the caller as a success. The pipelines in this package pair a mutation
	 * with the expiry that bounds it, so a swallowed failure is a key stranded
	 * with no TTL: the shape #269 already paid for once.
	 *
	 * Resolving with `null` is **not** a failure: it is the WATCH-abort signal,
	 * which the refresh-token-family CAS loop reads as "conflict, retry".
	 */
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for SessionRPRegistry adapters. Declares the hash ops +
 * multi pipeline that `createRedisSidHash` consumes.
 */
export interface SessionRPRegistryClient {
	/**
	 * Remove the key, reclaiming its memory on a background thread (Redis
	 * `UNLINK`). This key holds every relying party registered against one
	 * session and is deleted during logout; `DEL` would free all of them
	 * inline on the connection every other adapter shares (#291).
	 */
	unlink(key: string): Promise<number>;
	hSet(key: string, field: string, value: string): Promise<number>;
	/**
	 * Cursor-based iteration over the hash's field/value pairs (Redis
	 * `HSCAN`), yielding one pair at a time.
	 *
	 * Replaces `hVals`, whose reply size was bounded by nothing but how many
	 * relying parties a session had accumulated (#291). `HSCAN` guarantees
	 * that a field present for the whole iteration is returned at least once,
	 * so a field may be yielded more than once and consumers must de-duplicate.
	 */
	hScanIterator(
		key: string,
		opts?: { COUNT?: number },
	): AsyncIterable<readonly [field: string, value: string]>;
	multi(): SessionRPRegistryMultiClient;
	pExpireAt(key: string, msTimestamp: number): Promise<number>;
	/** Non-pipeline variant of `pExpireGT`. See multi-client for semantics. */
	pExpireGT(key: string, msTimestamp: number): Promise<number>;
}

// --- SessionSidSortedSetClient ---------------------------------------------

/**
 * Chainable transaction pipeline returned by `SessionSidSortedSetClient.multi()`.
 */
export interface SessionSidSortedSetMultiClient {
	pExpireAt(key: string, msTimestamp: number): SessionSidSortedSetMultiClient;
	/**
	 * Safely set the key's expiry under concurrent writes (D-10 / CR-3).
	 *
	 * Effective semantics:
	 *   - If the key has no TTL, set it to `msTimestamp` (first-write case).
	 *   - If the key has a TTL ≥ `msTimestamp`, leave it unchanged
	 *     (truncation prevented under stale-`expiresAt` races).
	 *   - If the key has a TTL < `msTimestamp`, raise it to `msTimestamp`
	 *     (legitimate extension allowed).
	 *
	 * Implemented as a `PEXPIREAT … NX` + `PEXPIREAT … GT` pair (Redis 7.0+
	 * flags). A bare `PEXPIREAT … GT` is insufficient: Redis treats a
	 * non-volatile key as having infinite TTL for `GT`, so the GT clause
	 * silently no-ops on first write. The NX clause covers that bootstrap
	 * gap; the GT clause provides the truncation guard once a TTL exists.
	 *
	 * Requires Redis 7.0+. v0.5.1 pins the floor to Redis 7.2 LTS.
	 */
	pExpireGT(key: string, msTimestamp: number): SessionSidSortedSetMultiClient;
	zAdd(
		key: string,
		entry: { score: number; value: string },
		opts?: { NX: true },
	): SessionSidSortedSetMultiClient;
	/**
	 * Execute the queued commands.
	 *
	 * **MUST reject when any queued command failed.** A driver that reports
	 * per-command errors inside the reply — ioredis resolves with one
	 * `[error, result]` tuple per command and does not reject, because `EXEC`
	 * itself succeeded — has to be adapted here, or a refused write is handed
	 * to the caller as a success. The pipelines in this package pair a mutation
	 * with the expiry that bounds it, so a swallowed failure is a key stranded
	 * with no TTL: the shape #269 already paid for once.
	 *
	 * Resolving with `null` is **not** a failure: it is the WATCH-abort signal,
	 * which the refresh-token-family CAS loop reads as "conflict, retry".
	 */
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for SessionFamilyIndex and SessionFederationIndex adapters.
 * Both adapters share this interface (same sorted-set operations, different
 * slot identities in ComponentMap).
 */
export interface SessionSidSortedSetClient {
	/**
	 * Remove the key, reclaiming its memory on a background thread (Redis
	 * `UNLINK`). This key holds every refresh-token family (or federation)
	 * linked to one session and is deleted during logout; `DEL` would free all
	 * of them inline on the connection every other adapter shares (#291).
	 */
	unlink(key: string): Promise<number>;
	multi(): SessionSidSortedSetMultiClient;
	pExpireAt(key: string, msTimestamp: number): Promise<number>;
	/** Non-pipeline variant of `pExpireGT`. See multi-client for semantics. */
	pExpireGT(key: string, msTimestamp: number): Promise<number>;
	zAdd(key: string, entry: { score: number; value: string }, opts?: { NX: true }): Promise<number>;
	/**
	 * Members between the two inclusive ranks, in ascending score order.
	 *
	 * Callers page by rank rather than passing `0, -1`: the reply size of a
	 * whole-set read grows with how heavily linked the session is (#291).
	 */
	zRange(key: string, start: number, stop: number): Promise<string[]>;
	zRem(key: string, member: string): Promise<number>;
}

// --- Subject-keyed clients (#321) ------------------------------------------

/**
 * Backing client for the `SubjectSessionIndex` adapter (#321).
 *
 * A **new** interface rather than a widening of {@link SessionSidSortedSetClient},
 * for two reasons. Widening would be a breaking change for every custom
 * implementation of that interface — the call #269 already faced — and it would
 * push score-range operations onto the sid-keyed adapters, which have no use
 * for them: every member of a sid-keyed set shares the one session's expiry, so
 * a single key-level TTL retires the whole set at once and `zRange` by rank is
 * all they ever need.
 *
 * A subject-keyed set cannot make that assumption. One subject's sessions
 * expire on their own clocks, so "the live ones" is a score range and pruning
 * is a score range — which is exactly why `createMemorySidSortedSet` was not
 * reused on the in-process side either.
 *
 * The score is the member's **expiry in epoch milliseconds**, so
 * `zRangeByScore(key, now, "+inf")` is precisely "sessions still live" and
 * `zRemRangeByScore(key, "-inf", now)` is precisely the GC sweep.
 */
export interface SubjectSessionIndexClient {
	multi(): SubjectSessionIndexMultiClient;
	zAdd(key: string, entry: { score: number; value: string }): Promise<number>;
	/** Members whose score is in `[min, max]`, ascending. */
	zRangeByScore(key: string, min: number | "-inf", max: number | "+inf"): Promise<string[]>;
	/** Remove members whose score is in `[min, max]` — the GC sweep. */
	zRemRangeByScore(key: string, min: number | "-inf", max: number | "+inf"): Promise<number>;
	zRem(key: string, member: string): Promise<number>;
	/**
	 * Remove the key, reclaiming its memory on a background thread (Redis
	 * `UNLINK`).
	 *
	 * `UNLINK` and not `DEL` for the reason #291 established: this key holds
	 * every live session of one subject, and `removeBySubject` is called on the
	 * credential-change path, on the connection every other adapter in this
	 * package shares. `DEL` frees every member inline — a latency spike during
	 * a password reset, paid by every other caller on the socket.
	 */
	unlink(key: string): Promise<number>;
}

/**
 * Pipeline half of {@link SubjectSessionIndexClient}, carrying the **write**
 * path only.
 *
 * A member and the key expiry that bounds it are queued together, because a
 * mutation whose expiry silently failed is a key stranded with no TTL — the
 * shape #269 paid for. Reads are not pipelined: `exec` hands back the driver's
 * raw reply, and having the adapter reach into it would put one driver's
 * `[error, result]` tuple shape into code that is supposed to be
 * vendor-agnostic.
 */
export interface SubjectSessionIndexMultiClient {
	zAdd(key: string, entry: { score: number; value: string }): SubjectSessionIndexMultiClient;
	/** See {@link SessionSidSortedSetMultiClient.pExpireGT} for the NX+GT semantics. */
	pExpireGT(key: string, msTimestamp: number): SubjectSessionIndexMultiClient;
	/** See {@link SessionSidSortedSetMultiClient.exec} — MUST reject on a queued failure. */
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for the `SubjectRevocation` adapter (#321).
 *
 * `setWatermarkMonotonic` is **not** `set(key, value, "PX", ttl)`, even though
 * the value is one string and the shape looks like it should be. The watermark
 * is monotonic: two credential changes in quick succession, the second computed
 * on a replica whose clock is behind, must not move the line backwards and
 * resurrect every token the first one killed. A last-writer-wins `SET` does
 * exactly that, and a client-side read-compare-write loses the same race one
 * round-trip later. The comparison therefore happens **on the server**, in one
 * command, and the same guard covers the entry's own expiry — shortening an
 * in-force watermark would retire the line while tokens it must refuse are
 * still presentable.
 */
export interface SubjectRevocationClient {
	get(key: string): Promise<string | null>;
	/**
	 * Atomically store `max(existing, beforeMs)` at `key` with expiry
	 * `max(existing, expiresAtMs)`, creating the key when absent.
	 *
	 * An **expired** key is absent, so the guard does not resurrect a lapsed
	 * watermark's larger value — a fresh reset after the previous watermark
	 * timed out starts from the new value.
	 *
	 * Resolves with the watermark in force after the write.
	 */
	setWatermarkMonotonic(key: string, beforeMs: number, expiresAtMs: number): Promise<number>;
}

// --- FederationTokenStoreClient --------------------------------------------

/**
 * Backing client for FederationTokenStore adapters. Declares `get`, `set`
 * (two overloads: PX form, and PX+NX form for atomic insert-only),
 * single-key `del`, variadic `unlink` for the batched removal in
 * `removeBySid`, the SET primitives backing the per-session key index
 * (`sAddWithTtl` / `sRem` / `sScanIterator`), `scanIterator` for the legacy
 * keyspace-scan migration fallback, and `compareAndDelete` for atomic
 * advisory-lock release.
 *
 * The plain-PX `set` overload always succeeds with `"OK"` per Redis
 * `SET key value PX ms` protocol; the PX+NX overload returns `"OK"` on
 * insert or `null` when the key already existed.
 */
export interface FederationTokenStoreClient {
	get(key: string): Promise<string | null>;
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	/**
	 * Remove one key (Redis `DEL`).
	 *
	 * Single-key by signature, not just by convention: the two callers left —
	 * `delete(sid, name)` and the corrupt-envelope self-heal in `get` — each
	 * remove exactly one small string, where `DEL`'s inline free costs nothing.
	 * Everything that removes more than one key at a time goes through `unlink`
	 * below. A variadic `del` would leave the choice open at each call site,
	 * which is how the batched removal came to block the shared connection in
	 * the first place (#291).
	 */
	del(key: string): Promise<number>;
	/**
	 * Remove `keys`, reclaiming their memory on a background thread (Redis
	 * `UNLINK`).
	 *
	 * `removeBySid` deletes a whole session's federation records at once, on
	 * the connection every other adapter in this package shares. `DEL` frees
	 * every value inline, so that batch is time the server spends serving
	 * nobody — a latency spike on an end-user logout, paid by every other
	 * caller on the socket. `UNLINK` returns as soon as the keys are
	 * unreferenced.
	 */
	unlink(...keys: string[]): Promise<number>;
	/**
	 * Add `member` to the SET at `key` and ensure the key expires no earlier
	 * than `ttlMs` from now — **atomically**, as one indivisible operation.
	 *
	 * The pair must not be separable, for the reason `RateLimiterClient`
	 * documents at length below: a process death between the add and the
	 * expiry leaves the key with **no TTL at all**, and this key is a session's
	 * federation index — a persistent one outlives the session it describes and
	 * accumulates forever.
	 *
	 * Required expiry behaviour, matching the `PEXPIRE … NX` + `PEXPIRE … GT`
	 * pair the sid-keyed session adapters use (D-10):
	 *   - key has no TTL → set it (first-write bootstrap; a bare `GT` no-ops
	 *     here, because Redis treats a non-volatile key as infinite-TTL)
	 *   - key has a nearer TTL → raise it
	 *   - key has a further TTL → leave it alone
	 *
	 * The index must outlive every envelope it points at, and every envelope
	 * write resets that envelope's expiry to `ttlMs` from now, so the newest
	 * write always carries the furthest deadline.
	 *
	 * @param ttlMs Relative expiry in milliseconds — the store's configured
	 *   TTL, not the access token's expiry.
	 */
	sAddWithTtl(key: string, member: string, ttlMs: number): Promise<void>;
	/** Remove one member from the SET at `key` (Redis `SREM`). */
	sRem(key: string, member: string): Promise<number>;
	/**
	 * Cursor-based iteration over the members of the SET at `key`
	 * (Redis `SSCAN`), so a session linked to many federations is read in
	 * bounded pages rather than as one unbounded `SMEMBERS` reply.
	 *
	 * `SSCAN` guarantees that a member present for the whole iteration is
	 * returned at least once — consumers must tolerate duplicates.
	 */
	sScanIterator(key: string, opts?: { COUNT?: number }): AsyncIterable<string>;
	scanIterator(opts: { MATCH: string; COUNT?: number }): AsyncIterable<string>;
	/**
	 * Atomically compare the value stored at `key` to `expectedValue` and
	 * delete the key only on match.
	 *
	 * This is the only safe lock-release primitive: a plain `del(key)` after a
	 * separate `get(key)` has a race window between the two commands during
	 * which a TTL-expired holder can evict a freshly-acquired lock owned by
	 * another caller. Implementations MUST use a server-side atomic mechanism
	 * — Lua `EVAL` on Redis standalone / Sentinel, or a transaction-equivalent
	 * primitive on Cluster-mode deployments where `EVAL` is disabled.
	 *
	 * Built-in `makeIoredisClients()` implements this via a Lua compare-and-
	 * delete script with `EVALSHA` caching and `EVAL` fallback on `NOSCRIPT`.
	 *
	 * @param key - The Redis key to check and conditionally delete.
	 * @param expectedValue - The value the caller expects to find at `key`.
	 * @returns `true` if the key was deleted (caller was the lock holder);
	 *          `false` if the stored value did not match (caller is no longer
	 *          the holder — a different process acquired the lock).
	 */
	compareAndDelete(key: string, expectedValue: string): Promise<boolean>;
}

// --- RateLimiterClient -----------------------------------------------------

/**
 * Backing client for RateLimiter adapters. Declares one method, because the
 * increment and its expiry have to happen together (#269).
 *
 * This used to be `incr` + `expire`, with the limiter calling `expire` only
 * when `incr` returned 1. A process death or an `expire` error in between left
 * the key with **no TTL at all**, so it never reset: every later window saw a
 * count above the limit and that key's client was 429'd permanently. The
 * `failMode` policy could not save it either — the check itself succeeded, it
 * just kept answering "denied".
 *
 * Collapsing the pair into one method moves atomicity from the caller's
 * discipline into the contract, where an implementation cannot get it wrong by
 * omission.
 */
export interface RateLimiterClient {
	/**
	 * Increment `key`'s counter and return the new value, ensuring the key
	 * carries a TTL — **atomically**, as one indivisible operation.
	 *
	 * Required behaviour:
	 *
	 *   - increment the counter, creating the key at 1 when absent
	 *   - if the key has no expiry, set it to `ttlSeconds`
	 *   - if the key already has one, leave it alone: the window starts at the
	 *     first request, and refreshing it on every hit would let a steady
	 *     stream of traffic hold a counter open indefinitely
	 *   - return the post-increment count
	 *
	 * Setting the expiry when it is *missing* rather than only when the count
	 * is 1 is what repairs a key already stranded without one — a count-based
	 * guard never fires for such a key, because its count never returns to 1.
	 *
	 * Lua is the obvious implementation (see `makeIoredisClients`) but is not
	 * required; anything indivisible satisfies the contract.
	 *
	 * @param ttlSeconds Window length. Always a positive integer — callers
	 *   reject non-positive specs, because `EXPIRE key 0` deletes the key and
	 *   would turn the limiter into a no-op.
	 */
	incrementWithTtl(key: string, ttlSeconds: number): Promise<number>;
}

// --- CodeRepositoryClient --------------------------------------------------

/**
 * Backing client for CodeRepository adapters. Declares only the four Redis
 * commands `RedisCodeRepository` consumes: `set` with PX expiry (always
 * succeeds with `"OK"`), unconditional `get`, atomic `getDel` (Redis 6.2+),
 * and unconditional `del`.
 *
 * Per OR-9 (Wave 5d). The repository is rewritten in v0.5.1 to consume an
 * externally-provided typed wrapper instead of constructing its own
 * node-redis client; aligns with the per-purpose client convention
 * established by D-2 v2 and consumed via `bootstrapComponents`.
 */
export interface CodeRepositoryClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	get(key: string): Promise<string | null>;
	getDel(key: string): Promise<string | null>;
	del(key: string): Promise<number>;
}

// ---------------------------------------------------------------------------
// ComponentMap augmentations: backing-client slots consumed by redis adapters.
//
// These augmentations are visible to any TypeScript consumer that imports
// from `@o3co/auth-provider-redis`. Consumers wiring redis backends via
// `bootstrapComponents` get the slot types automatically.
// ---------------------------------------------------------------------------

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly challengeStoreClient?: ChallengeStoreClient;
		readonly accessTokenDenylistClient?: AccessTokenDenylistClient;
		readonly replaySeenSetClient?: ReplaySeenSetClient;
		readonly refreshTokenFamilyClient?: RefreshTokenFamilyClient;
		readonly userSessionStoreClient?: UserSessionStoreClient;
		readonly sessionRPRegistryClient?: SessionRPRegistryClient;
		readonly sessionFamilyIndexClient?: SessionSidSortedSetClient;
		readonly sessionFederationIndexClient?: SessionSidSortedSetClient;
		readonly subjectSessionIndexClient?: SubjectSessionIndexClient;
		readonly subjectRevocationClient?: SubjectRevocationClient;
		readonly federationTokenStoreClient?: FederationTokenStoreClient;
		readonly rateLimiterClient?: RateLimiterClient;
		readonly codeRepositoryClient?: CodeRepositoryClient;
	}
}
