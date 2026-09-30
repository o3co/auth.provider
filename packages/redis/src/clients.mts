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

import type {
	MfaLockoutPolicy,
	MfaSubjectAttemptOutcome,
	MfaSubjectHold,
} from "@o3co/auth-provider-core";

// ---------------------------------------------------------------------------
// Per-purpose backing-client contracts for the Redis adapters in this
// package, in Redis-command terms (see README, "Backing-client contract").
// Each has a slot in the ComponentMap augmentation at the end of this file.
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
 * Backing client for AccessTokenDenylist adapters
 * (`createRedisAccessTokenDenylist`).
 *
 * `set` is the plain PX form with no `NX`: re-revoking a jti is idempotent and
 * last-write-wins on the expiry, matching the memory adapter. That is also why
 * this is separate from {@link ReplaySeenSetClient}, whose whole contract
 * turns on the `NX` return value.
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
	 * Execute the queued commands. Same contract as
	 * {@link SessionSidSortedSetMultiClient.exec}: MUST reject when any queued
	 * command failed; `null` is the WATCH-abort signal, which the CAS loop
	 * reads as "conflict, retry".
	 */
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for RefreshTokenFamilyStore adapters. The `duplicate()` method
 * returns a `DisposableRefreshTokenFamilyClient` bound to a new underlying
 * connection, required for WATCH/MULTI/EXEC CAS isolation.
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
 * Backing client for UserSessionStore adapters: exactly the methods
 * `createRedisUserSessionStore` consumes.
 *
 * `set` has two overloads:
 *  - plain PX form: always `"OK"` (Redis `SET key value PX ms`), never null.
 *  - PX+NX form: atomic insert-only, used by `create`. Returns `"OK"` on
 *    insert, `null` when the key already existed.
 */
export interface UserSessionStoreClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	get(key: string): Promise<string | null>;
	del(key: string): Promise<number>;
	/**
	 * Replace the value at `key` with `next` only while it still holds exactly
	 * `expected`, keeping the key's TTL — as one indivisible operation. `true`
	 * when it replaced; `false`, and nothing written, when the key held
	 * anything else or nothing.
	 *
	 * The step-up write (`recordSecondFactor`; ADR
	 * 2026-09-25-multi-factor-authentication, D9): the adapter reads the
	 * session, computes the next one and writes it through this, re-reading
	 * when it loses. A GET then a SET would let two step-ups in flight each
	 * overwrite the other's factor; a write that set a new expiry, or none,
	 * would change how long the session lives. `makeIoredisClients` answers it
	 * with a script (`SET … KEEPTTL`, Redis 6.0+).
	 */
	replaceIfUnchanged(key: string, expected: string, next: string): Promise<boolean>;
}

// --- SessionRPRegistryClient -----------------------------------------------

/**
 * Chainable transaction pipeline returned by `SessionRPRegistryClient.multi()`.
 */
export interface SessionRPRegistryMultiClient {
	hSet(key: string, field: string, value: string): SessionRPRegistryMultiClient;
	pExpireAt(key: string, msTimestamp: number): SessionRPRegistryMultiClient;
	/**
	 * Safely set the key's expiry under concurrent writes; see
	 * {@link SessionSidSortedSetMultiClient.pExpireGT} for the NX+GT semantics.
	 */
	pExpireGT(key: string, msTimestamp: number): SessionRPRegistryMultiClient;
	/**
	 * Execute the queued commands. Same contract as
	 * {@link SessionSidSortedSetMultiClient.exec}: MUST reject when any queued
	 * command failed; `null` is the WATCH-abort signal, not a failure.
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
	 * inline on the connection every other adapter shares.
	 */
	unlink(key: string): Promise<number>;
	hSet(key: string, field: string, value: string): Promise<number>;
	/**
	 * Cursor-based iteration over the hash's field/value pairs (Redis
	 * `HSCAN`), yielding one pair at a time.
	 *
	 * Cursor-based because a whole-hash reply grows with however many relying
	 * parties a session has accumulated. `HSCAN` guarantees that a field
	 * present for the whole iteration is returned at least once, so a field
	 * may be yielded more than once and consumers must de-duplicate.
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
	 * Safely set the key's expiry under concurrent writes:
	 *   - no TTL → set it to `msTimestamp` (first write);
	 *   - TTL ≥ `msTimestamp` → leave it unchanged (no truncation under
	 *     stale-`expiresAt` races);
	 *   - TTL < `msTimestamp` → raise it to `msTimestamp`.
	 *
	 * Implemented as a `PEXPIREAT … NX` + `PEXPIREAT … GT` pair. A bare
	 * `PEXPIREAT … GT` is insufficient: Redis treats a non-volatile key as
	 * having infinite TTL for `GT`, so it silently no-ops on first write; the
	 * NX clause covers that gap. Requires Redis 7.0+ (the tested floor is
	 * 7.2 LTS).
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
	 * with no TTL.
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
	 * of them inline on the connection every other adapter shares.
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
	 * whole-set read grows with how heavily linked the session is.
	 */
	zRange(key: string, start: number, stop: number): Promise<string[]>;
	zRem(key: string, member: string): Promise<number>;
}

// --- Subject-keyed clients -------------------------------------------------

/**
 * Backing client for the `SubjectSessionIndex` adapter. Unlike a sid-keyed
 * set ({@link SessionSidSortedSetClient}), whose members share one session's
 * expiry and one key-level TTL, one subject's sessions expire on their own
 * clocks, so "the live ones" and pruning are score ranges. The score is the
 * member's **expiry in epoch milliseconds**: `zRangeByScore(key, now,
 * "+inf")` is "sessions still live" and `zRemRangeByScore(key, "-inf", now)`
 * is the GC sweep.
 */
export interface SubjectSessionIndexClient {
	multi(): SubjectSessionIndexMultiClient;
	zAdd(key: string, entry: { score: number; value: string }): Promise<number>;
	/**
	 * Sweep members whose expiry has passed, then return the ones that remain,
	 * **evaluating "has passed" against the store's own clock**.
	 *
	 * One operation rather than a range-remove plus a range-read, because the
	 * boundary has to be a single value and must not be the calling replica's
	 * `Date.now()`: scores are written by whichever replica handled the login,
	 * and judging them on another replica's clock drops live sessions early or
	 * keeps expired ones listed. The store is the one clock every replica
	 * shares.
	 */
	pruneExpiredAndList(key: string): Promise<string[]>;
	zRem(key: string, member: string): Promise<number>;
	/**
	 * Remove the key, reclaiming its memory on a background thread (Redis
	 * `UNLINK`). This key holds every live session of one subject, and
	 * `removeBySubject` runs on the credential-change path, on the connection
	 * every adapter in this package shares; `DEL` would free every member
	 * inline — a latency spike during a password reset, paid by every other
	 * caller on the socket.
	 */
	unlink(key: string): Promise<number>;
}

/**
 * Pipeline half of {@link SubjectSessionIndexClient}, carrying the **write**
 * path only. A member and the key expiry that bounds it are queued together,
 * because a mutation whose expiry silently failed is a key stranded with no
 * TTL. Reads are not pipelined: parsing `exec`'s raw reply would put one
 * driver's `[error, result]` tuple shape into vendor-agnostic code.
 */
export interface SubjectSessionIndexMultiClient {
	zAdd(key: string, entry: { score: number; value: string }): SubjectSessionIndexMultiClient;
	/** See {@link SessionSidSortedSetMultiClient.pExpireGT} for the NX+GT semantics. */
	pExpireGT(key: string, msTimestamp: number): SubjectSessionIndexMultiClient;
	/** See {@link SessionSidSortedSetMultiClient.exec} — MUST reject on a queued failure. */
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for the `SubjectRevocation` adapter.
 *
 * The boundary write is **not** a plain `SET`: the watermark is monotonic.
 * Two credential changes in quick succession, the second computed on a
 * replica whose clock is behind, must not move the line backwards and
 * resurrect every token the first one killed. A last-writer-wins `SET` does
 * exactly that, and a client-side read-compare-write loses the same race one
 * round-trip later, so the comparison happens **on the server**, in one
 * command. The same guard covers the entry's own expiry: shortening an
 * in-force watermark would retire the line while tokens it must refuse are
 * still presentable.
 */
export interface SubjectRevocationClient {
	get(key: string): Promise<string | null>;
	/**
	 * Atomically advance one or both of a subject's revocation boundaries on
	 * one key, monotonically, and retain the record for as long as either
	 * needs (ADR 2026-09-17-federation-grants-offline-delegation, D13).
	 *
	 * - `mode: "all"` advances both boundaries to `max(existing, beforeMs)`,
	 *   each taken independently. This is `revokeBefore`.
	 * - `mode: "sessions"` advances the sessions boundary alone and leaves the
	 *   grants boundary exactly as it was, including absent.
	 *
	 * The retained expiry is the largest of the key's current expiry, the
	 * caller's `expiresAtMs`, and — when a grants boundary is in force — that
	 * boundary plus `grantRetentionMs`. A key with no expiry keeps none. An
	 * **expired** key is absent, so the guard does not resurrect a lapsed
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
 * Backing client for FederationTokenStore adapters: `get`, `set` (PX form,
 * always `"OK"`; PX+NX form for atomic insert-only, `null` when the key
 * already existed), single-key `del`, variadic `unlink` for the batched
 * removal in `removeBySid`, the SET primitives backing the per-session key
 * index (`sAddWithTtl` / `sRem` / `sScanIterator`), `scanIterator` for the
 * legacy keyspace-scan migration fallback, and `compareAndDelete` for atomic
 * advisory-lock release.
 */
export interface FederationTokenStoreClient {
	get(key: string): Promise<string | null>;
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	/**
	 * Remove one key (Redis `DEL`). Single-key by signature, not just by
	 * convention: its callers — `delete(sid, name)` and the corrupt-envelope
	 * self-heal in `get` — each remove one small string, where `DEL`'s inline
	 * free costs nothing, and anything removing more goes through `unlink`. A
	 * variadic `del` would leave that choice open at each call site.
	 */
	del(key: string): Promise<number>;
	/**
	 * Remove `keys`, reclaiming their memory on a background thread (Redis
	 * `UNLINK`). `removeBySid` deletes a whole session's federation records at
	 * once, on the connection every adapter in this package shares; `DEL`
	 * would free every value inline — a latency spike on an end-user logout,
	 * paid by every other caller on the socket.
	 */
	unlink(...keys: string[]): Promise<number>;
	/**
	 * Add `member` to the SET at `key` and ensure the key expires no earlier
	 * than `ttlMs` from now — **atomically**, as one indivisible operation.
	 *
	 * The pair must not be separable (see `RateLimiterClient`): a process death
	 * between the add and the expiry leaves this session's federation index
	 * with **no TTL at all**, outliving the session and accumulating forever.
	 *
	 * Required expiry behaviour, matching the `PEXPIRE … NX` + `PEXPIRE … GT`
	 * pair the sid-keyed session adapters use:
	 *   - key has no TTL → set it (a bare `GT` no-ops here, because Redis
	 *     treats a non-volatile key as infinite-TTL)
	 *   - key has a nearer TTL → raise it
	 *   - key has a further TTL → leave it alone
	 *
	 * The index must outlive every envelope it points at; every envelope write
	 * resets that envelope's expiry to `ttlMs` from now, so the newest write
	 * always carries the furthest deadline.
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
	 * The only safe lock-release primitive: a `get(key)` then a `del(key)`
	 * leaves a window in which a TTL-expired holder can evict a lock another
	 * caller has just acquired. Implementations MUST use a server-side atomic
	 * mechanism — Lua `EVAL` on Redis standalone / Sentinel, or a
	 * transaction-equivalent primitive on Cluster deployments where `EVAL` is
	 * disabled. `makeIoredisClients()` uses a Lua compare-and-delete script
	 * with `EVALSHA` caching and `EVAL` fallback on `NOSCRIPT`.
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
 * Backing client for RateLimiter adapters. One method, because the increment
 * and its expiry have to happen together: with a separate `expire`, a process
 * death or an `expire` error in between leaves the key with **no TTL at
 * all**, so it never resets and that key's client is 429'd permanently — and
 * `failMode` cannot help, since the check itself succeeds. One method puts
 * atomicity in the contract, where an implementation cannot omit it.
 */
export interface RateLimiterClient {
	/**
	 * Increment `key`'s counter and return the new value, ensuring the key
	 * carries a TTL — **atomically**, as one indivisible operation:
	 *
	 *   - increment the counter, creating the key at 1 when absent
	 *   - if the key has no expiry, set it to `ttlSeconds`
	 *   - if the key already has one, leave it alone: the window starts at the
	 *     first request, and refreshing it on every hit would let a steady
	 *     stream of traffic hold a counter open indefinitely
	 *   - return the post-increment count
	 *
	 * Setting the expiry when it is *missing*, rather than when the count is 1,
	 * repairs a key already stranded without one, whose count never returns to
	 * 1. Lua is the obvious implementation (see `makeIoredisClients`);
	 * anything indivisible satisfies the contract.
	 *
	 * @param ttlSeconds Window length. Always a positive integer — callers
	 *   reject non-positive specs, because `EXPIRE key 0` deletes the key and
	 *   would turn the limiter into a no-op.
	 */
	incrementWithTtl(key: string, ttlSeconds: number): Promise<number>;

	/**
	 * `incrementWithTtl`, also returning the counter key's `PTTL` after the
	 * increment, read in the same indivisible step. The limiter turns it into
	 * `RateLimitDecision.resetAt`, and the guard turns that into the
	 * `Retry-After` on a 429.
	 *
	 * Optional so a custom client written against the one-method contract
	 * keeps compiling and working; a limiter given such a client reports no
	 * reset time.
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
 * Backing client for CodeRepository adapters: the four Redis commands
 * `RedisCodeRepository` consumes — `set` with PX expiry (always `"OK"`),
 * unconditional `get`, atomic `getDel` (Redis 6.2+), and unconditional
 * `del`. The repository consumes this externally provided wrapper (via
 * `bootstrapComponents`) instead of constructing its own client.
 */
export interface CodeRepositoryClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	get(key: string): Promise<string | null>;
	getDel(key: string): Promise<string | null>;
	del(key: string): Promise<number>;
}

// --- DeviceCodeStoreClient -------------------------------------------------

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
	/** Epoch milliseconds, set by an approval: the `now` the decision was made at. */
	readonly approvedAtMs?: string;
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
 * Backing client for the `DeviceCodeStore` adapter.
 *
 * Semantic operations rather than a raw `eval`, as {@link RateLimiterClient}
 * and {@link SubjectSessionIndexClient}: `create`, `approve`/`deny` and
 * `poll` must be **indivisible**, and a contract expressed as Redis commands
 * would leave that to the caller's discipline. Lua is the obvious
 * implementation (see `makeIoredisClients`) but not required — anything
 * atomic that reads and writes the pair satisfies this. `poll` matters most:
 * as `HGETALL` then `DEL`, two concurrent polls both observe `approved`, and
 * one human approval becomes two access tokens.
 */
export interface DeviceCodeStoreClient {
	/**
	 * Write the record and the index, both insert-only, both expiring at
	 * `expiresAtMs` — atomically. Resolves `false` when either key already
	 * exists, and writes nothing in that case: a collision is a generator
	 * failure, and overwriting would hand a new device the previous one's
	 * pending approval. `false` is the collision signal the endpoint re-draws
	 * for, so a client that cannot tell which happened — a reply it does not
	 * understand — rejects instead, and the endpoint answers an outage.
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
	 *   - `expiresAtMs <= nowMs` → `expired`, and the pair is deleted. Measured
	 *     against the caller's clock, not the key's TTL: a record still inside
	 *     its TTL must answer `expired` once the timestamp has passed.
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

// --- ConsentStoreClient ----------------------------------------------------

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
	 * A required key: a client whose `find` forgot to pass the field on
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
	 * removed. A required key: a store that forgot to pass it would
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
 * Backing client for the `ConsentStore` adapter.
 *
 * Semantic operations rather than commands, as {@link DeviceCodeStoreClient},
 * because `grant` is the port's union: as `HGET` then `HSET` from the client,
 * two browsers consenting to different scopes at once each write back what
 * they read, and one grant is lost. Lua is the obvious implementation (see
 * `makeIoredisClients`) but anything indivisible over the one key satisfies
 * this. Every operation touches exactly the one key it is handed, so this
 * client needs no hash tag to run on Cluster.
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
	 * contributes nothing, as `find` reports it absent. `grantedAt` and the
	 * expiry are the new record's, and so is the key's TTL: set from
	 * `expiry.ttlMs`, or removed when there is no expiry.
	 */
	grant(key: string, input: GrantConsentInput): Promise<void>;
	/** Remove the record. Resolves whether there was one. */
	revoke(key: string): Promise<boolean>;
}

// --- PendingConsentStoreClient ---------------------------------------------

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
 * Backing client for the `PendingConsentStore` adapter.
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

// --- FederationGrantStoreClient -------------------------------------------

/**
 * A federation grant as it lives in Redis: one HASH per grant, every field a
 * string, beside one STRING holding the sealed credential (ADR
 * 2026-09-17-federation-grants-offline-delegation, D16). The field names are
 * part of the contract, because the scripts read them by name.
 *
 * Two fields are arithmetic rather than record: `retentionMs` (the tombstone
 * retention when the grant was created) and `expiresAtMs` (the
 * authorization's expiry, outside the authenticated text). They decide what
 * Redis reclaims and what a write may touch — never what a caller is told,
 * which is judged on the authenticated text; a rewritten `expiresAtMs` can
 * make a key linger, not disclose a credential past the consented expiry.
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
	 * `undefined` when the upstream gave no `Retry-After`. A required key, as
	 * `upstreamCode` is: a store that forgot to pass one would leave a
	 * `rate_limited` stamp with the default backoff where the upstream's
	 * `Retry-After` was longer (both held to the ceiling), or lose the code
	 * that says the user has to come back. A client tells "none" by the value
	 * (`=== undefined`), as `makeIoredisClients` does, not by the key.
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
 * The indivisible steps the Redis federation grant store is built from.
 * Every method here is one round trip, and every write is one script: a
 * guard evaluated in the client and a write sent after it would let a
 * concurrent activation, refresh or revocation land in between.
 *
 * A refused write says `null` and nothing else: the record may change again
 * before the caller looks, so the port has it re-read and re-evaluated, and
 * a reason here would oblige two adapters to agree on which precondition
 * wins when several fail at once.
 *
 * Keys are passed in whole: the store owns the layout, and a script that
 * discovered key names inside Lua would not be safe to run on a Cluster.
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
	 * counting the stamps in a row, and bumps no version. The version is
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
 * What an intent admission answered. `unchanged` is the
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
 * Vendor-facing half of acquisition's records: semantic operations rather
 * than commands, because each one is a single guarded script.
 *
 * Every key one of these touches is derived inside the script from `prefix`,
 * which ends in the constant `{intents}` hash tag, so a script may reach the
 * consent an intent points at, or the transaction under a stored state,
 * without the caller naming a key it does not know yet, all in one Cluster
 * slot. Nothing here spans this keyspace and a grant's (`fg:{<id>}:…`).
 *
 * The records travel as text this package's codec produced. A driver neither
 * reads nor writes their fields; the scripts compare only the flat fields
 * beside them — a deadline, a binding, a connection, a pair — so no script
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

// --- MfaFactorStoreClient --------------------------------------------------

/**
 * What a Redis server says about keeping what it is written — read at boot
 * by the two MFA store modules (ADR 2026-09-25-multi-factor-authentication,
 * D12). Each part is `undefined` when it could not be read: the server
 * refused the question (`refusal`), or answered without the value.
 */
export interface RedisDurability {
	/** `INFO memory`'s `maxmemory_policy`, or `CONFIG GET maxmemory-policy` where INFO does not say. */
	readonly maxmemoryPolicy: string | undefined;
	/** `INFO persistence`'s `aof_enabled`. */
	readonly appendOnly: boolean | undefined;
	/** `CONFIG GET save` is not empty: RDB snapshots are taken. Asked only when AOF is off. */
	readonly snapshots: boolean | undefined;
	/** The first reply that refused a question — an unknown or renamed command, `NOPERM`, a disabled command — as the driver raised it. Logged by its projection only. */
	readonly refusal: unknown;
}

/**
 * What an update writes over a factor record's version and its mutable part,
 * each as the text the record keeps.
 */
export interface MfaFactorRecordUpdateInput {
	/** The version the record must still be at, as decimal text. */
	readonly expectedVersion: string;
	/** The version it is at afterwards, as decimal text. */
	readonly nextVersion: string;
	/** The new mutable part: one line of JSON. */
	readonly mutable: string;
}

/**
 * Backing client for the `MfaFactorStore` adapter (ADR
 * 2026-09-25-multi-factor-authentication, D7): one hash per subject, a field
 * per factor.
 *
 * A factor's value is three lines — `<version>\n<fixed>\n<mutable>` — where
 * `<version>` is decimal text and `<fixed>` and `<mutable>` are one line of
 * JSON each (`JSON.stringify` never writes a raw line feed). The split lets
 * `update` be one indivisible step that never decodes the JSON: it compares
 * the version as text, keeps the fixed part byte for byte, and writes the
 * new version and mutable part beside it. A script that decoded and
 * re-encoded the record would change it (`cjson` writes an empty array as
 * `{}`), so none does. Every operation touches the one key it is handed, so
 * this client needs no hash tag to run on Cluster.
 */
export interface MfaFactorStoreClient {
	/** Every field of the hash at `key` and its value (`HGETALL`); `{}` when there is none. */
	list(key: string): Promise<Readonly<Record<string, string>>>;
	/** Write `value` under `field` only while the field is absent (`HSETNX`). Resolves whether it wrote. */
	create(key: string, field: string, value: string): Promise<boolean>;
	/**
	 * Atomically: while the value under `field` is at `input.expectedVersion`,
	 * replace its version and mutable part, keep its fixed part, and resolve
	 * the value as written; `null` when the field is absent, at another
	 * version, or not three lines.
	 */
	update(key: string, field: string, input: MfaFactorRecordUpdateInput): Promise<string | null>;
	/** Remove `field` (`HDEL`). Idempotent. */
	remove(key: string, field: string): Promise<void>;
	/** Remove the whole hash (`DEL`). Idempotent. */
	removeAll(key: string): Promise<void>;
	/**
	 * What the server says about keeping what it is written. A reply
	 * that refuses a question leaves that part unread; any other reply error,
	 * and a server that cannot be asked at all, rejects.
	 */
	durability(): Promise<RedisDurability>;
}

// --- MfaTransactionStoreClient --------------------------------------------

/** What an update writes, as the transaction's hash keeps it. */
export interface MfaTransactionUpdateInput {
	/** The version the transaction must still be at, as decimal text. */
	readonly expectedVersion: string;
	/**
	 * The value its `incarnation` field must still hold: the random value
	 * `create` wrote, so a transaction consumed and created again under the
	 * same id, at the same version, is never written with a patch that was
	 * checked against the one before it.
	 */
	readonly incarnation: string;
	/** Fields to write, and the text each is written as. */
	readonly set: Readonly<Record<string, string>>;
	/** Fields to remove. */
	readonly clear: readonly string[];
}

/**
 * A subject's lock-state keys. Both carry the subject's hash tag: every
 * operation on the state is one script over the two.
 */
export interface MfaSubjectKeys {
	/**
	 * HASH: `seq`, the order counter; `r:<id>` → `<seq>|<atMs>` for each
	 * attempt in the consecutive run; `p:<id>` → `<seq>` for each reservation
	 * not yet settled; `held` → `1` while an episode of refusals is under way.
	 * A field of any other kind is ignored.
	 */
	readonly lock: string;
	/** ZSET: the attempts the rolling week counts, each scored by its time. */
	readonly week: string;
}

export interface ReserveMfaSubjectAttemptInput {
	/** The caller's time, which every hold is judged on. */
	readonly nowMs: number;
	readonly policy: MfaLockoutPolicy;
	/** The id the attempt is recorded under when it is let through. */
	readonly reservation: string;
}

export type ReserveMfaSubjectAttemptReply =
	| { readonly ok: true }
	| {
			readonly ok: false;
			readonly hold: MfaSubjectHold;
			/** Milliseconds from `nowMs` until an attempt may be reserved; `null` for the hard hold. */
			readonly retryAfterMs: number | null;
			/** Whether this refusal begins an episode, as the port's `first`. */
			readonly first: boolean;
	  };

export interface NoteMfaExemptSuccessInput {
	/** The time of the exempt success: the run ends up to it. */
	readonly nowMs: number;
}

/**
 * Backing client for the `MfaTransactionStore` adapter (ADR
 * 2026-09-25-multi-factor-authentication, D8, D21, D25).
 *
 * Semantic operations: every one the port calls atomic is a read, a decision
 * and a write, which Redis makes one step only as a script (see
 * `makeIoredisClients`). The operations here read a transaction's `version`,
 * `incarnation`, `attempts`, `challenge` and `expiresAtMs` fields by name,
 * and never decode its `record`.
 *
 * The subject state's decisions — backoff, weekly budget and hard limit —
 * are the port's rules, judged on the caller's `nowMs`;
 * what is reclaimed is judged on the server's clock, never later than a day
 * after it stops counting (`MFA_CLOCK_SKEW_ALLOWANCE_MS`). A stored value an
 * operation cannot read is refused with an error, never read as a state that
 * holds nothing.
 */
export interface MfaTransactionStoreClient {
	/**
	 * Write the transaction's `fields` into the hash at `key`, and its deadline
	 * (`PEXPIREAT deadlineMs`), only while no live one is there. Resolves
	 * whether it wrote.
	 */
	create(
		key: string,
		fields: Readonly<Record<string, string>>,
		deadlineMs: number,
	): Promise<boolean>;
	/** Every field of the hash at `key` (`HGETALL`); `{}` when there is none. */
	read(key: string): Promise<Readonly<Record<string, string>>>;
	/**
	 * Atomically: while the transaction is at `expectedVersion` and its
	 * incarnation, write `set`, remove `clear`, add one to `version`, and
	 * resolve every field as written; `null` otherwise. The deadline stays.
	 */
	update(
		key: string,
		input: MfaTransactionUpdateInput,
	): Promise<Readonly<Record<string, string>> | null>;
	/**
	 * Atomically: `attempts` + 1 while that is within `max`; past it — or on
	 * a count that is not a number — the transaction is deleted and the
	 * attempts it had are answered with `ok: false`. No transaction, or one
	 * gone at `nowMs` — at or past the deadline its `expiresAtMs` field holds
	 * as decimal text, or holding none that is a finite number — is
	 * `{ ok: false, attempts: 0 }`, spending nothing: the store's clock is the
	 * transaction's, whatever the server's says, and the key is left to its
	 * deadline on the server's.
	 */
	reserveAttempt(
		key: string,
		max: number,
		nowMs: number,
	): Promise<{ readonly ok: boolean; readonly attempts: number }>;
	/**
	 * Atomically: the `challenge` field, removed, while the version is
	 * `expectedVersion` and the transaction is not gone at `nowMs` (as
	 * `reserveAttempt` judges it); `null` otherwise, taking nothing.
	 */
	takeChallenge(key: string, expectedVersion: string, nowMs: number): Promise<string | null>;
	/** Atomically: every field, and the hash deleted, while the version is `expectedVersion`; `null` otherwise. */
	consume(key: string, expectedVersion: string): Promise<Readonly<Record<string, string>> | null>;
	/** The port's `reserveSubjectAttempt`, one script over both keys. */
	reserveSubjectAttempt(
		keys: MfaSubjectKeys,
		input: ReserveMfaSubjectAttemptInput,
	): Promise<ReserveMfaSubjectAttemptReply>;
	/** The port's `settleSubjectAttempt`, one script over both keys; a reservation not in flight changes nothing. */
	settleSubjectAttempt(
		keys: MfaSubjectKeys,
		reservation: string,
		outcome: MfaSubjectAttemptOutcome,
	): Promise<void>;
	/** The port's `noteExemptSuccess`, one script over both keys. */
	noteExemptSuccess(keys: MfaSubjectKeys, input: NoteMfaExemptSuccessInput): Promise<void>;
	/** Remove both keys. */
	clearSubjectState(keys: MfaSubjectKeys): Promise<void>;
	/** Record the email-proof requirement at `key`, with no TTL. Idempotent. */
	requireEmailProof(key: string): Promise<void>;
	/** Whether the requirement is recorded at `key`. */
	emailProofRequired(key: string): Promise<boolean>;
	/** Remove the requirement at `key` (`DEL`); resolves whether this call removed it. */
	consumeEmailProof(key: string): Promise<boolean>;
	/** Write a session's email proof `value` at `key`, replacing any, expiring `ttlMs` from when the server takes it (`SET … PX`). */
	recordSessionEmailProof(key: string, value: string, ttlMs: number): Promise<void>;
	/** The session's email proof at `key` (`GET`); `null` when there is none. */
	sessionEmailProof(key: string): Promise<string | null>;
	/** As `MfaFactorStoreClient.durability`: the requirement must be kept as the factors are. */
	durability(): Promise<RedisDurability>;
}

// ---------------------------------------------------------------------------
// ComponentMap augmentations: backing-client slots consumed by redis adapters,
// visible to any TypeScript consumer that imports from
// `@o3co/auth-provider-redis`.
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
		readonly deviceCodeStoreClient?: DeviceCodeStoreClient;
		readonly consentStoreClient?: ConsentStoreClient;
		readonly pendingConsentStoreClient?: PendingConsentStoreClient;
		readonly federationGrantStoreClient?: FederationGrantStoreClient;
		readonly federationGrantIntentStoreClient?: FederationGrantIntentStoreClient;
		readonly mfaFactorStoreClient?: MfaFactorStoreClient;
		readonly mfaTransactionStoreClient?: MfaTransactionStoreClient;
	}
}
