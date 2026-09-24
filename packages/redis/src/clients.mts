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
	/**
	 * Sweep members whose expiry has passed, then return the ones that remain,
	 * **evaluating "has passed" against the store's own clock**.
	 *
	 * One operation rather than a range-remove plus a range-read, because the
	 * boundary has to be a single value and it must not be the calling
	 * replica's `Date.now()`. Scores are written from whichever replica handled
	 * the login; comparing them against whichever replica handles the read is
	 * two host clocks, and the skew between them drops live sessions early or
	 * keeps expired ones listed. The store is the one clock every replica
	 * shares, which is the whole reason this index moved off in-process state.
	 */
	pruneExpiredAndList(key: string): Promise<string[]>;
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
	 * Atomically advance one or both of a subject's revocation boundaries on
	 * one key, monotonically, and retain the record for as long as either needs
	 * (#593, D13).
	 *
	 * Replaces `setWatermarkMonotonic`, which could express only one boundary.
	 * It is a deliberate break rather than an addition: a driver that kept the
	 * old method and silently ignored a `mode` argument would answer every
	 * sessions-only stamp by revoking the subject's grants, which is precisely
	 * the operation the caller asked not to perform.
	 *
	 * - `mode: "all"` advances both boundaries to `max(existing, beforeMs)`,
	 *   each taken independently. This is `revokeBefore`, and it is what every
	 *   caller written before #593 means.
	 * - `mode: "sessions"` advances the sessions boundary alone and leaves the
	 *   grants boundary exactly as it was, including absent.
	 *
	 * The retained expiry is the largest of the key's current expiry, the
	 * caller's `expiresAtMs`, and — when a grants boundary is in force — that
	 * boundary plus `grantRetentionMs`. A key with no expiry keeps none.
	 *
	 * An **expired** key is absent, so the guard does not resurrect a lapsed
	 * record's larger values.
	 *
	 * Resolves with the stored value, exactly as written.
	 */
	setRevocationBoundaries(
		key: string,
		mode: "all" | "sessions",
		beforeMs: number,
		expiresAtMs: number,
		grantRetentionMs: number,
	): Promise<string>;
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

	/**
	 * `incrementWithTtl`, also reporting the key's remaining window (#458).
	 *
	 * Same required behaviour, plus: return the counter key's `PTTL` after
	 * the increment, read in the same indivisible step. The limiter turns it
	 * into `RateLimitDecision.resetAt`, and the guard turns that into the
	 * `Retry-After` on a 429 — which behind Redis was missing altogether,
	 * while the memory adapter had it.
	 *
	 * Optional so a custom client written against the one-method contract
	 * keeps compiling and working; a limiter given such a client reports no
	 * reset time, which is exactly what it reported before.
	 */
	incrementWithTtlAndPttl?(key: string, ttlSeconds: number): Promise<RateLimitIncrement>;
}

/** What {@link RateLimiterClient.incrementWithTtlAndPttl} answers. */
export interface RateLimitIncrement {
	/** The post-increment count. */
	readonly count: number;
	/** The counter key's remaining TTL in milliseconds (`PTTL`), read after the increment. */
	readonly pttl: number;
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

// --- DeviceCodeStoreClient (#433) ------------------------------------------

/**
 * Where one device authorization lives: `codeKeyPrefix + deviceCode` holds
 * the record, `userKeyPrefix + userCode` holds the device code it belongs to.
 *
 * Every method takes both, because every mutation touches both — `create`
 * writes the pair, `poll` consumes the pair, and `approve`/`deny` reach the
 * record *through* the index. **The two prefixes must hash to the same
 * slot.** A script may only touch keys in the slot it was routed to, and the
 * key it derives from the index is not one the caller could declare up front.
 * `createRedisDeviceCodeStore` guarantees this with one constant `{devauth}`
 * hash tag in both prefixes; a custom keyspace has to guarantee it too.
 */
export interface DeviceCodeKeyspace {
	readonly codeKeyPrefix: string;
	readonly userKeyPrefix: string;
}

/**
 * The record as it lives in Redis: one hash, every field a string. The field
 * names are part of the contract because the scripts read them by name.
 *
 * Numbers are decimal strings and the scope lists are JSON arrays, so a scope
 * value is stored byte-for-byte rather than split on a separator it might
 * contain. Optional fields are *absent* rather than empty: the memory adapter
 * distinguishes "asked for no scope" from "asked for `[]`", and so does this.
 */
export interface DeviceCodeRecordFields {
	readonly userCode: string;
	readonly clientId: string;
	/** Epoch milliseconds. What `poll` measures `expired` against — not the TTL. */
	readonly expiresAtMs: string;
	/** Seconds. Grown in place by `poll` on `slow_down`, so the gate measures against the grown value. */
	readonly intervalSeconds: string;
	readonly status: "pending" | "approved" | "denied";
	/** JSON array. Absent when the device asked for no scope at all. */
	readonly requestedScope?: string;
	/** Set by an approval. */
	readonly subject?: string;
	/** JSON array, set by an approval. */
	readonly grantedScope?: string;
	/** Epoch milliseconds of the previous poll. Absent until the first. */
	readonly lastPolledAtMs?: string;
}

export interface CreateDeviceCodeRecordInput {
	readonly deviceCode: string;
	readonly userCode: string;
	/**
	 * The deadline both keys expire at, in whole epoch milliseconds within the
	 * Date range. The script writes the pair before its `PEXPIREAT`, so a
	 * deadline Redis refused there would leave both keys with no TTL:
	 * `createRedisDeviceCodeStore` therefore refuses an expiry outside the
	 * Date range before calling `create`, and rounds the one it passes up to a
	 * whole millisecond. A client called some other way must hold to the same.
	 * The record's own `fields.expiresAtMs` stays the exact expiry.
	 */
	readonly expiresAtMs: number;
	readonly fields: DeviceCodeRecordFields;
}

export type DeviceCodeDecisionInput =
	| { readonly decision: "denied" }
	| {
			readonly decision: "approved";
			readonly subject: string;
			/**
			 * Omitted grants `requestedScope` whole. Supplied, it is intersected
			 * with `requestedScope` **inside the operation** — the caller may
			 * narrow, never widen, and reading the record first to intersect
			 * client-side would be the second read the port rules out.
			 */
			readonly grantedScope?: readonly string[];
	  };

export type DeviceCodeDecisionReply =
	| { readonly kind: "ok"; readonly fields: DeviceCodeRecordFields }
	| { readonly kind: "not_found" }
	| { readonly kind: "expired" }
	| { readonly kind: "already_decided"; readonly status: "approved" | "denied" };

export type DeviceCodePollReply =
	| { readonly kind: "not_found" }
	| { readonly kind: "expired" }
	| { readonly kind: "denied" }
	| { readonly kind: "pending" }
	| { readonly kind: "slow_down"; readonly intervalSeconds: number }
	| { readonly kind: "approved"; readonly fields: DeviceCodeRecordFields };

/**
 * Backing client for the `DeviceCodeStore` adapter (#433).
 *
 * Five semantic operations rather than a raw `eval`, the shape
 * {@link RateLimiterClient} and {@link SubjectSessionIndexClient} use: the
 * port's contract is that `create`, `approve`/`deny` and `poll` are
 * **indivisible**, and a contract expressed as the Redis commands to issue
 * would leave that indivisibility to the caller's discipline. Lua is the
 * obvious implementation (see `makeIoredisClients`) but not required —
 * anything atomic that reads and writes the pair satisfies this.
 *
 * Each operation says what it must guarantee. The one that matters most is
 * `poll`: as `HGETALL` then `DEL`, two concurrent polls both observe
 * `approved`, and one human approval becomes two access tokens.
 */
export interface DeviceCodeStoreClient {
	/**
	 * Write the record and the index, both insert-only, both expiring at
	 * `expiresAtMs` — atomically. Resolves `false` when either key already
	 * exists, and writes nothing in that case: a collision is a generator
	 * failure, and overwriting would hand a new device the previous one's
	 * pending approval.
	 */
	create(keys: DeviceCodeKeyspace, input: CreateDeviceCodeRecordInput): Promise<boolean>;
	/**
	 * The record behind `userCode`, or `null` when it is absent, past
	 * `expiresAtMs` as of `nowMs`, or already decided. An expired record is
	 * reclaimed on the way, as the memory adapter does.
	 */
	findPending(
		keys: DeviceCodeKeyspace,
		userCode: string,
		nowMs: number,
	): Promise<DeviceCodeRecordFields | null>;
	/**
	 * Move the record behind `userCode` from `pending` to the decision —
	 * atomically with the check that it *is* pending. A second decision must
	 * answer `already_decided` with the first, never overwrite it: a user who
	 * denied a phishing prompt could otherwise be talked into "just trying
	 * again".
	 */
	decide(
		keys: DeviceCodeKeyspace,
		userCode: string,
		nowMs: number,
		input: DeviceCodeDecisionInput,
	): Promise<DeviceCodeDecisionReply>;
	/**
	 * Atomically: enforce the polling interval, read the status, and — when
	 * approved or denied — delete the pair so the answer is given once.
	 *
	 * Required behaviour, in this order:
	 *
	 *   - absent → `not_found`
	 *   - `expiresAtMs <= nowMs` → `expired`, and the pair is deleted. This is
	 *     measured against the caller's clock, not the key's TTL: the port's
	 *     contract is the timestamp, and a record still inside its TTL must
	 *     answer `expired` once the timestamp has passed.
	 *   - polled within `intervalSeconds` of the previous poll → `slow_down`,
	 *     with `intervalSeconds` grown by `slowDownIncrementSeconds` **and
	 *     written back**, so the next gate measures against the grown value
	 *     (RFC 8628 §3.5: "increased by 5 seconds for this and all subsequent
	 *     requests"). The gate runs before the status read, so an over-eager
	 *     poller is not rewarded with `approved`.
	 *   - `denied` → `denied`, and the pair is deleted
	 *   - `pending` → `pending`
	 *   - `approved` → `approved` with the record, and the pair is deleted
	 */
	poll(
		keys: DeviceCodeKeyspace,
		deviceCode: string,
		nowMs: number,
		slowDownIncrementSeconds: number,
	): Promise<DeviceCodePollReply>;
	/** Delete the record and its index together. Absence is not an error. */
	remove(keys: DeviceCodeKeyspace, deviceCode: string): Promise<void>;
}

// --- ConsentStoreClient (#561) ---------------------------------------------

/**
 * A consent record as it lives in Redis: one hash per (`sub`, `clientId`),
 * every field a string. The field names are part of the contract because the
 * scripts read them by name.
 *
 * The scopes are one JSON array rather than a Redis set, so a scope value is
 * stored byte-for-byte and the order they were first granted in survives —
 * and so the record and its `grantedAt` / `expiresAt` are one key that one
 * script rewrites whole. The hash has no `expiresAt` field for a consent
 * recorded until revoked; a client reports that as `expiresAt: undefined`.
 */
export interface ConsentRecordFields {
	/** JSON array of the scopes agreed to. */
	readonly scopes: string;
	/** Epoch milliseconds. */
	readonly grantedAt: string;
	/**
	 * Epoch milliseconds; `undefined` when the hash holds none — until revoked.
	 * A required key (#626): a client whose `find` forgot to pass the field on
	 * would have the adapter read a consent meant to lapse as one until revoked
	 * — unless, as `makeIoredisClients`' script does, `find` already refuses a
	 * record past its expiry.
	 */
	readonly expiresAt: string | undefined;
}

export interface GrantConsentInput {
	/** The caller's clock, in epoch milliseconds: what "still live" is judged against. */
	readonly nowMs: number;
	/** The scopes this grant adds. */
	readonly scopes: readonly string[];
	readonly grantedAt: number;
	/**
	 * The new record's expiry. `undefined`, the record is until revoked and the
	 * key carries **no** TTL afterwards — whatever an earlier grant set is
	 * removed. A required key (#626): a store that forgot to pass it would
	 * record every consent until revoked.
	 */
	readonly expiry:
		| {
				/** Epoch milliseconds, stored as the record's `expiresAt`. */
				readonly expiresAt: number;
				/**
				 * The key's TTL in milliseconds — a safety net for a record nobody reads
				 * again, never what expiry is judged by. Not positive: the new record is
				 * dead on arrival, so the key is removed and nothing is written.
				 */
				readonly ttlMs: number;
		  }
		| undefined;
}

/**
 * Backing client for the `ConsentStore` adapter (#561).
 *
 * Semantic operations rather than commands, the shape
 * {@link DeviceCodeStoreClient} uses, because `grant` is the port's union:
 * as `HGET` then `HSET` from the client, two browsers consenting to
 * different scopes at once each write back what they read, and one grant is
 * lost. Lua is the obvious implementation (see `makeIoredisClients`) but not
 * required — anything indivisible over the one key satisfies this.
 *
 * Every operation touches exactly the one key it is handed, so this client
 * needs no hash tag to run on Cluster.
 */
export interface ConsentStoreClient {
	/**
	 * The record at `key`, or `null` when there is none or its `expiresAt` is
	 * at or before `nowMs`. An expired record is removed on the way, in the same
	 * step as the read — a separate `DEL` could remove a grant written in
	 * between. The fields are returned as stored; judging their shape is the
	 * adapter's.
	 */
	find(key: string, nowMs: number): Promise<ConsentRecordFields | null>;
	/**
	 * Atomically replace the record at `key` with one whose scopes are the
	 * union of `input.scopes` and those of the record already there — only if
	 * that record is still live at `input.nowMs` and well-formed (`scopes` a
	 * JSON array of strings, `grantedAt` a number); an expired or corrupt one
	 * contributes nothing, as `find` reports it absent. `grantedAt` and the expiry are the new record's, and so is the
	 * key's TTL: set from `expiry.ttlMs`, or removed when there is no expiry.
	 */
	grant(key: string, input: GrantConsentInput): Promise<void>;
	/** Remove the record. Resolves whether there was one. */
	revoke(key: string): Promise<boolean>;
}

// --- PendingConsentStoreClient (#561) --------------------------------------

/**
 * Where parked consent requests live: `recordKeyPrefix + challenge` holds a
 * request, `sessionKeyPrefix + sessionId` holds the challenges that session
 * has parked, in the order it parked them.
 *
 * **The two prefixes must hash to the same slot.** `consume` arrives with the
 * challenge alone and takes the request out of its session's index in the
 * same script, reaching the index through the record — a key the caller could
 * not declare up front — and `set` reaches the session's other records
 * through the index. `createRedisPendingConsentStore` guarantees this with
 * one constant `{pending}` hash tag in both prefixes; a custom keyspace has to
 * guarantee it too.
 */
export interface PendingConsentKeyspace {
	readonly recordKeyPrefix: string;
	readonly sessionKeyPrefix: string;
}

export interface ParkPendingConsentInput {
	readonly challenge: string;
	readonly sessionId: string;
	/** Epoch milliseconds on the caller's clock. What expiry is judged by — not the TTL. */
	readonly expiresAt: number;
	/** The caller's clock, in epoch milliseconds. */
	readonly nowMs: number;
	/**
	 * The record key's TTL in milliseconds, a safety net only; the session index
	 * is kept alive at least as long as its longest-lived member. Not positive:
	 * the request is dead on arrival and is not parked.
	 */
	readonly ttlMs: number;
	/** The request, serialised by the adapter, stored and returned byte-for-byte. */
	readonly record: string;
	/** How many requests the session may have parked once this one is. A positive integer. */
	readonly perSessionLimit: number;
}

/**
 * Backing client for the `PendingConsentStore` adapter (#561).
 *
 * Semantic operations, for the reason {@link DeviceCodeStoreClient} gives:
 * `consume` is the port's reason to exist — as a `GET` then a `DEL`, two
 * answers in flight for one challenge are both handed the request, and a
 * denial and an acceptance both apply — and the per-session bound only holds
 * if the index and the records move together.
 */
export interface PendingConsentStoreClient {
	/**
	 * Park `input.record` under its challenge — atomically:
	 *
	 *   - a request already parked under the challenge is replaced, and leaves
	 *     its own session's index (which may be another session's)
	 *   - requests of this session that have expired at `nowMs`, or whose record
	 *     is already gone, leave its index before the bound is judged
	 *   - while the session holds `perSessionLimit` or more, the one it parked
	 *     first is removed, record and index entry together
	 *   - the record is written with its TTL and appended to the index
	 */
	set(keys: PendingConsentKeyspace, input: ParkPendingConsentInput): Promise<void>;
	/**
	 * The serialised request, or `null` when there is none or it has expired at
	 * `nowMs`. Does not spend a live request; an expired one is removed with its
	 * index entry on the way.
	 */
	get(keys: PendingConsentKeyspace, challenge: string, nowMs: number): Promise<string | null>;
	/**
	 * The serialised request, removed with its index entry in the same step —
	 * or `null` when there was nothing live to remove. An expired request is
	 * removed too, and answers `null`.
	 */
	consume(keys: PendingConsentKeyspace, challenge: string, nowMs: number): Promise<string | null>;
	/**
	 * Remove the request parked under `challenge`, with its index entry — but
	 * only while the stored serialisation is still exactly `record`, compared
	 * and removed atomically. Resolves whether it was removed.
	 *
	 * The adapter's reclaim for a record `get` read and found corrupt. The
	 * comparison is what makes it safe to issue after the read: a valid request
	 * re-parked under the challenge in between is a different value, and stays.
	 */
	discard(keys: PendingConsentKeyspace, challenge: string, record: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// ComponentMap augmentations: backing-client slots consumed by redis adapters.
//
// These augmentations are visible to any TypeScript consumer that imports
// from `@o3co/auth-provider-redis`. Consumers wiring redis backends via
// `bootstrapComponents` get the slot types automatically.
// ---------------------------------------------------------------------------

// --- FederationGrantStoreClient (#593) -------------------------------------

/**
 * A federation grant as it lives in Redis: one HASH per grant, every field a
 * string, beside one STRING holding the sealed credential (#593, D16). The
 * field names are part of the contract, because the scripts read them by name.
 *
 * Two fields are arithmetic rather than record: `retentionMs` is the
 * tombstone retention as it was when the grant was created, and `expiresAtMs`
 * repeats the authorization's expiry outside the authenticated text. They
 * decide what Redis reclaims and what a write may touch — never what a caller
 * is told. Every answer is judged on the authenticated text, so a `expiresAtMs`
 * someone rewrote in the keyspace can make a key linger; it cannot make a
 * credential be disclosed past the expiry the upstream consented to.
 */
export interface FederationGrantHashFields {
	/** The layout's own version, so a later one can be told apart rather than misread. */
	readonly format: string;
	/** JSON `[id, subject, clientId, connection, createdAtMs]`. */
	readonly base: string;
	readonly status: string;
	readonly version: string;
	readonly retentionMs: string;
	/** The canonical authorization text, byte for byte as it was sealed under. Absent before authorization. */
	readonly authorization?: string;
	/** The authorization's `expiresAt`, in epoch milliseconds. Absent before authorization. */
	readonly expiresAtMs?: string;
	/** Guard fields, repeated outside the authenticated text so a script can compare them. */
	readonly identityRevision?: string;
	readonly upstreamIssuer?: string;
	readonly upstreamSubject?: string;
	/** The current intent's opaque handle, JSON-encoded, and when it lapses. Absent when there is none. */
	readonly intentHandle?: string;
	readonly intentExpiresAt?: string;
	readonly lastUsedAt?: string;
	/** JSON `[reason, atMs, judgedAgainst]`. */
	readonly ineligible?: string;
	readonly failureAt?: string;
	readonly failureKind?: string;
	readonly failureCount?: string;
	readonly failureRetryAfterSeconds?: string;
	readonly failureUpstreamCode?: string;
	readonly revokedBy?: string;
	readonly revokedAt?: string;
}

export interface CreatePendingFederationGrantInput {
	/** The caller's clock, in epoch milliseconds. */
	readonly nowMs: number;
	/** {@link FederationGrantHashFields.base}, already encoded. */
	readonly base: string;
	/** The intent's handle, JSON-encoded. */
	readonly handle: string;
	readonly intentExpiresAtMs: number;
	readonly retentionMs: number;
}

export interface NameFederationGrantIntentInput {
	readonly nowMs: number;
	readonly handle: string;
	readonly intentExpiresAtMs: number;
}

export interface RetireFederationGrantIntentInput {
	readonly nowMs: number;
	/** When given, the pointer is removed only if this is the handle it holds. */
	readonly handle?: string;
}

export interface ActivateFederationGrantInput {
	readonly nowMs: number;
	/** The intent's handle, JSON-encoded: only the current one activates. */
	readonly handle: string;
	/** The canonical authorization text, byte for byte as the credential was sealed under. */
	readonly authorization: string;
	/** The authorization's expiry, for the arithmetic the scripts do. */
	readonly expiresAtMs: number;
	/** Guard fields, repeated outside the authenticated text so a script can compare them. */
	readonly identityRevision: string;
	readonly upstreamIssuer: string;
	readonly upstreamSubject: string;
	/** The sealed credential. */
	readonly credential: string;
}

export interface ReplaceFederationGrantCredentialsInput {
	readonly nowMs: number;
	readonly expectedVersion: number;
	readonly credential: string;
	/** The ineligibility marker as JSON `[reason, atMs, judgedAgainst]`, or `null` to remove it. */
	readonly ineligible: string | null;
}

export interface RequireFederationGrantReauthorizationInput {
	readonly nowMs: number;
	readonly expectedVersion: number;
}

export interface RevokeFederationGrantInput {
	readonly atMs: number;
	readonly by: string;
}

export interface NoteFederationGrantRefreshFailureInput {
	readonly nowMs: number;
	readonly expectedVersion: number;
	/** When the failure happened, which is what the row is measured from — not `nowMs`. */
	readonly atMs: number;
	readonly kind: string;
	readonly rowMs: number;
	/**
	 * `undefined` when the upstream gave no `Retry-After`. A required key (#626),
	 * as `upstreamCode` is: a store that forgot to pass one would leave a
	 * `rate_limited` stamp with the default backoff where the upstream's
	 * `Retry-After` was longer (both held to the ceiling), or lose the code
	 * that says the user has to come back.
	 *
	 * Both keys are always present now, so a client tells "none" by the value
	 * (`=== undefined`), as `makeIoredisClients` does — not by whether the key
	 * is there.
	 */
	readonly retryAfterSeconds: number | undefined;
	/** For `rejected`: the upstream's error code. `undefined` otherwise. */
	readonly upstreamCode: string | undefined;
}

/** What one read returns: the record and its credential as they were at one instant. */
export interface FederationGrantSnapshot {
	readonly fields: FederationGrantHashFields;
	/** `null` when the key is not there. An empty string is a credential, and not that. */
	readonly credential: string | null;
}

/**
 * The indivisible steps the Redis federation grant store is built from
 * (#593, D16). Every method here is one round trip, and every write is one
 * script: a guard evaluated in the client and a write sent after it would let
 * a concurrent activation, refresh or revocation land in between.
 *
 * A refused write says `null` and nothing else. The record may change again
 * before the caller looks, so the port has it re-read and re-evaluated (D2),
 * and a reason here would oblige two adapters to agree on which precondition
 * wins when several fail at once.
 *
 * Keys are passed in whole rather than built here: the store owns the layout,
 * and a script that discovered key names inside Lua would not be safe to run
 * on a Cluster.
 */
export interface FederationGrantStoreClient {
	/**
	 * Creates the `pending` record at `grantKey`, at version 1, with its
	 * intent, and takes any credential at `credKey` with it. Refuses when a
	 * record is already there — however far ahead the caller's clock is — and
	 * when the intent's expiry is not after `nowMs`.
	 */
	createPending(
		grantKey: string,
		credKey: string,
		input: CreatePendingFederationGrantInput,
	): Promise<FederationGrantHashFields | null>;
	/** The record and its credential, read together. `null` when there is no record. */
	snapshot(grantKey: string, credKey: string): Promise<FederationGrantSnapshot | null>;
	/** Replaces the intent pointer of an `active` or `reauthorization_required` record, and nothing else. */
	nameIntent(
		grantKey: string,
		input: NameFederationGrantIntentInput,
	): Promise<FederationGrantHashFields | null>;
	/** Removes the intent pointer of an `active` or `reauthorization_required` record, and nothing else. */
	retireIntent(
		grantKey: string,
		input: RetireFederationGrantIntentInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Takes the grant from its current intent to `active` under a new
	 * authorization, sealing the credential with it. Every guard is inside the
	 * script, including the current intent — `nameIntent` and `retireIntent`
	 * bump no version, so a version comparison cannot see a pointer that moved
	 * under a caller that read it.
	 *
	 * A renewal never re-points a grant: the identity revision and the upstream
	 * account must be the ones already recorded. The marker and the stamp of a
	 * failed refresh go with the authorization they were about; a use recorded
	 * before it stays.
	 */
	activate(
		grantKey: string,
		credKey: string,
		input: ActivateFederationGrantInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Replaces the credential of an `active` grant at `expectedVersion`, and
	 * the marker whole — a refresh that found the token eligible removes one.
	 * Forgets the stamp of a failed refresh, and moves no horizon: the
	 * credential's deadline is the authorization's expiry again.
	 */
	replaceCredentials(
		grantKey: string,
		credKey: string,
		input: ReplaceFederationGrantCredentialsInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Takes the credential and asks for the user, at `expectedVersion`. The
	 * only transition with no expiry guard: an upstream that says the
	 * credential is dead is believed whenever it says it. The marker stays,
	 * the horizon does not move.
	 */
	requireReauthorization(
		grantKey: string,
		credKey: string,
		input: RequireFederationGrantReauthorizationInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Ends the grant: the credential and the intent go, what it was authorized
	 * for stays, and the first revocation stays as it was recorded. No version
	 * guard — a revocation does not lose to a refresh in flight. A revocation
	 * moves no horizon, except for a grant that was never authorized and has
	 * no expiry to be retained from.
	 */
	revoke(
		grantKey: string,
		credKey: string,
		input: RevokeFederationGrantInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Stamps a failed refresh on an `active` grant at `expectedVersion`,
	 * counting the stamps in a row, and bumps no version (D12). The version is
	 * still compared: a failure that outlived its refresh must not install a
	 * backoff over a credential written since. Never dated back, and an equal
	 * instant counts onward.
	 */
	noteRefreshFailure(
		grantKey: string,
		input: NoteFederationGrantRefreshFailureInput,
	): Promise<FederationGrantHashFields | null>;
	/** Moves `lastUsedAt` forward, and never back. Writes nothing when there is no record. */
	touch(grantKey: string, atMs: number): Promise<void>;
	/**
	 * Reserves `member` in the subject's index at `horizonMs` — the instant the
	 * record stops answering — and pushes the index's own deadline to the last
	 * horizon it holds plus `allowanceMs`.
	 *
	 * The score only ever moves forward. Two writers lodging one ID both
	 * reserve, and the one whose record is created is not the one that reserved
	 * last: a reservation that lost must not pull the horizon back under the
	 * record that won. A reservation is never withdrawn, for the same reason.
	 */
	reserve(indexKey: string, member: string, horizonMs: number, allowanceMs: number): Promise<void>;
	/** Everything the index holds, nearest horizon first. */
	members(indexKey: string): Promise<readonly string[]>;
	/** `SET key token NX PX ttl`: whether this caller now holds the lock. */
	tryLock(lockKey: string, token: string, ttlMs: number): Promise<boolean>;
	/** Deletes the lock only while its value is still `token`: past the TTL it is somebody else's. */
	unlock(lockKey: string, token: string): Promise<void>;
	/**
	 * Drops members whose horizon passed more than `allowanceMs` before
	 * `clockMs` — the adapter's own clock, as a key TTL is, and never a
	 * caller's. Never by whether the record is there: the index and the record
	 * are different keys, so a member reserved for a record still being written
	 * would be dropped by that rule, and nothing would ever put it back.
	 */
	prune(indexKey: string, clockMs: number, allowanceMs: number): Promise<void>;
}

/**
 * What an intent admission answered (#593, D16, slice 6). `unchanged` is the
 * retry of a write whose answer the caller lost: the same record, already
 * there, its deadline untouched and its place against the bound not taken
 * twice.
 */
export interface FederationGrantIntentAdmission {
	readonly outcome: "created" | "unchanged" | "refused";
	readonly reason?: "limit" | "collision" | "closed" | "expired";
}

/** What answering a consent did, with the record the answer applied to. */
export interface FederationGrantConsentAnswered {
	readonly outcome: "empty" | "denied" | "accepted" | "state_collision";
	/** The intent, for a denial; the transaction, for an approval. */
	readonly record?: string;
}

/**
 * Vendor-facing half of acquisition's records (#593, D16, slice 6): semantic
 * operations rather than commands, because each one is a single guarded script.
 *
 * Every key one of these touches is derived inside the script from `prefix`,
 * which ends in the constant `{intents}` hash tag — so a script may reach the
 * consent an intent points at, or the transaction under a stored state, without
 * the caller naming a key it does not know yet, and every key it reaches is in
 * the same Cluster slot. Nothing here spans this keyspace and a grant's
 * (`fg:{<id>}:…`): supersession is enforced by the grant's own current-intent
 * pointer, and core orders the two writes.
 *
 * The records travel as text this package's codec produced. A driver neither
 * reads nor writes their fields; what the scripts compare are the flat fields
 * beside them — a deadline, a binding, a connection, a pair — so that no script
 * has to parse JSON to decide anything.
 */
export interface FederationGrantIntentStoreClient {
	/**
	 * Admits an intent: takes its place against the bound and writes the record,
	 * as one step. Prunes the bound's index on the SERVER's clock first, so a
	 * place is released by the passage of time and not by a caller.
	 */
	admitIntent(
		prefix: string,
		input: {
			readonly handle: string;
			readonly record: string;
			readonly expiresAtMs: number;
			readonly nowMs: number;
			/** Length-prefixed `(clientId, subject)`; the index this reservation belongs to. */
			readonly pair: string;
			/** Whether this intent takes a place at all — a reauthorization does not. */
			readonly counts: boolean;
			readonly limit: number;
			/** How long the index outlives its last member, so it never dies under one. */
			readonly reservationAllowanceMs: number;
		},
	): Promise<FederationGrantIntentAdmission>;

	/** The intent's text while it is live and the caller's clock is before its deadline. */
	readIntent(prefix: string, handle: string, nowMs: number): Promise<string | null>;

	/**
	 * Parks a challenge for a live intent, or hands back the one already parked
	 * for the same browser. A challenge another intent holds is never taken.
	 */
	parkConsent(
		prefix: string,
		input: {
			readonly handle: string;
			readonly challenge: string;
			readonly record: string;
			/** The browser this challenge is answerable from, as one comparable string. */
			readonly binding: string;
			readonly expiresAtMs: number;
			readonly nowMs: number;
		},
	): Promise<string | null>;

	/** The parked record, without spending it. */
	readConsent(prefix: string, challenge: string, nowMs: number): Promise<string | null>;

	/**
	 * Answers a challenge once: the challenge goes, the intent is spent, and an
	 * approval writes the transaction — or none of it happens. A denial releases
	 * the place against the bound; an approval keeps it until the flow ends.
	 */
	answerConsent(
		prefix: string,
		input: {
			readonly challenge: string;
			readonly binding: string;
			readonly nowMs: number;
			readonly decision: "accept" | "deny";
			readonly state?: string;
			readonly transaction?: string;
			readonly transactionExpiresAtMs?: number;
			readonly connection?: string;
		},
	): Promise<FederationGrantConsentAnswered>;

	/** Reads and removes the transaction, and only for the connection it belongs to. */
	consumeTransaction(
		prefix: string,
		input: {
			readonly state: string;
			readonly connection: string;
			readonly nowMs: number;
		},
	): Promise<string | null>;

	/** Closes the handle, drops what is left under it, releases its place — once. */
	finishIntent(prefix: string, handle: string, nowMs: number): Promise<void>;
}

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
		readonly deviceCodeStoreClient?: DeviceCodeStoreClient;
		readonly consentStoreClient?: ConsentStoreClient;
		readonly pendingConsentStoreClient?: PendingConsentStoreClient;
		readonly federationGrantStoreClient?: FederationGrantStoreClient;
		readonly federationGrantIntentStoreClient?: FederationGrantIntentStoreClient;
	}
}
