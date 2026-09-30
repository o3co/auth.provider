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
 * Clients for the session stores: the session record, the indexes keyed by sid, the subject's
 * session index and its revocation record. A pipeline's `exec` rejects when a queued command
 * failed, so no mutation is left without the expiry queued with it.
 */

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
