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

/**
 * The federation token store's client: the envelopes, their conditional writes, the per-session
 * index that finds them, and the atomic release of the store's advisory lock.
 */

/** What `replaceIfGeneration` writes, the deadline at or after which it writes nothing, and where it keeps its answer. */
export interface FederationTokenReplaceIfInput {
	/** The generation the stored value must carry: its wrapper's `g`. */
	readonly expected: string;
	/** The new stored value, carrying its new generation. */
	readonly value: string;
	/** The store TTL the value is written with (`PX`), in whole milliseconds. */
	readonly ttlMs: number;
	/** Epoch ms on the server's clock at or after which the write is refused (`late`), nothing read or written. */
	readonly deadlineMs: number;
	/**
	 * Where this write keeps its answer until `clockSkewMs` past `deadlineMs`
	 * (`SET … PXAT deadlineMs + clockSkewMs + 1`), on the record's Cluster slot:
	 * a copy of the write that reaches the server before then answers what the
	 * first copy answered and writes nothing.
	 */
	readonly replayKey: string;
	/**
	 * The clock skew the adapter allows between servers' clocks: the replay key
	 * outlives the deadline by it, so a server whose clock lags the one that
	 * kept the key (after a failover or a slot migration) still finds it before
	 * it would judge the copy on time.
	 */
	readonly clockSkewMs: number;
}

/** What `removeIfGeneration` checks, the deadline at or after which it writes nothing, and where it keeps its answer, as for `replaceIfGeneration`. */
export interface FederationTokenRemoveIfInput {
	readonly expected: string;
	readonly deadlineMs: number;
	readonly replayKey: string;
	readonly clockSkewMs: number;
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
	/**
	 * The stored value at `key` and the generation its wrapper carries, read in
	 * one atomic step: `null` when there is no key. A value the store's format
	 * wrote without a generation is given `candidate` in the same step, its TTL
	 * kept. Any other value is answered with the generation `""`. Implementations
	 * MUST be atomic (`makeIoredisClients()` runs one script).
	 */
	readVersioned(
		key: string,
		candidate: string,
	): Promise<{ raw: string; generation: string } | null>;
	/**
	 * Replace the value at `key` with `input.value` (`PX input.ttlMs`) only while
	 * the stored value's generation is `input.expected`, as one atomic step that
	 * first refuses at or after `input.deadlineMs` on the server's clock, then
	 * answers a copy of a write it already took from `input.replayKey`, writing
	 * nothing. `missing`: no key; `conflict`: another generation, or none;
	 * `late`: at or after the deadline, this copy wrote nothing (an earlier
	 * copy may have committed). Only the first `updated` writes.
	 */
	replaceIfGeneration(
		key: string,
		input: FederationTokenReplaceIfInput,
	): Promise<"updated" | "missing" | "conflict" | "late">;
	/** Delete `key` only while its value's generation is `input.expected`, as `replaceIfGeneration` checks. */
	removeIfGeneration(
		key: string,
		input: FederationTokenRemoveIfInput,
	): Promise<"removed" | "missing" | "conflict" | "late">;
	/**
	 * Raise the TTL of `key` to `ttlMs` from now when it is nearer (Redis
	 * `PEXPIRE … GT`): never lowers it, never creates the key, never adds a
	 * member.
	 */
	pExpireGT(key: string, ttlMs: number): Promise<void>;
}
