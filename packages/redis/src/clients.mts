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
// Per Phase 10 addendum §3 + v0.5.0 pre-tag interface review S3.
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
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for SessionRPRegistry adapters. Declares the hash ops +
 * multi pipeline that `createRedisSidHash` consumes.
 */
export interface SessionRPRegistryClient {
	del(key: string): Promise<number>;
	hSet(key: string, field: string, value: string): Promise<number>;
	hVals(key: string): Promise<string[]>;
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
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for SessionFamilyIndex and SessionFederationIndex adapters.
 * Both adapters share this interface (same sorted-set operations, different
 * slot identities in ComponentMap).
 */
export interface SessionSidSortedSetClient {
	del(key: string): Promise<number>;
	multi(): SessionSidSortedSetMultiClient;
	pExpireAt(key: string, msTimestamp: number): Promise<number>;
	/** Non-pipeline variant of `pExpireGT`. See multi-client for semantics. */
	pExpireGT(key: string, msTimestamp: number): Promise<number>;
	zAdd(key: string, entry: { score: number; value: string }, opts?: { NX: true }): Promise<number>;
	zRange(key: string, start: number, stop: number): Promise<string[]>;
	zRem(key: string, member: string): Promise<number>;
}

// --- FederationTokenStoreClient --------------------------------------------

/**
 * Backing client for FederationTokenStore adapters. Declares `get`, `set`
 * (two overloads: PX form, and PX+NX form for atomic insert-only),
 * variadic `del`, `scanIterator` for the cursor-based key scan used by
 * `removeBySid`, and `compareAndDelete` for atomic advisory-lock
 * release.
 *
 * The plain-PX `set` overload always succeeds with `"OK"` per Redis
 * `SET key value PX ms` protocol; the PX+NX overload returns `"OK"` on
 * insert or `null` when the key already existed.
 */
export interface FederationTokenStoreClient {
	get(key: string): Promise<string | null>;
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	del(...keys: string[]): Promise<number>;
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
 * Backing client for RateLimiter adapters. Declares only `incr` and `expire`
 * — the two methods `createRedisRateLimiter` consumes.
 */
export interface RateLimiterClient {
	incr(key: string): Promise<number>;
	expire(key: string, seconds: number): Promise<number>;
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
		readonly replaySeenSetClient?: ReplaySeenSetClient;
		readonly refreshTokenFamilyClient?: RefreshTokenFamilyClient;
		readonly userSessionStoreClient?: UserSessionStoreClient;
		readonly sessionRPRegistryClient?: SessionRPRegistryClient;
		readonly sessionFamilyIndexClient?: SessionSidSortedSetClient;
		readonly sessionFederationIndexClient?: SessionSidSortedSetClient;
		readonly federationTokenStoreClient?: FederationTokenStoreClient;
		readonly rateLimiterClient?: RateLimiterClient;
		readonly codeRepositoryClient?: CodeRepositoryClient;
	}
}
