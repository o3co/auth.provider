/**
 * Clients for the session stores: the session record, the subject's session index and its
 * revocation record. A pipeline's `exec` rejects when a queued command failed, so a mutation
 * whose paired expiry failed is never reported as written.
 */
import type { RedisDurability } from "./durability.mjs";
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
/**
 * Backing client for the `SubjectSessionIndex` adapter. One subject's sessions
 * expire on their own clocks, so "the live ones" and pruning are score ranges. The score is the
 * member's **expiry in epoch milliseconds**: `zRangeByScore(key, now,
 * "+inf")` is "sessions still live" and `zRemRangeByScore(key, "-inf", now)`
 * is the GC sweep.
 */
export interface SubjectSessionIndexClient {
    multi(): SubjectSessionIndexMultiClient;
    zAdd(key: string, entry: {
        score: number;
        value: string;
    }): Promise<number>;
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
    zAdd(key: string, entry: {
        score: number;
        value: string;
    }): SubjectSessionIndexMultiClient;
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
    pExpireGT(key: string, msTimestamp: number): SubjectSessionIndexMultiClient;
    /**
     * Execute the queued commands.
     *
     * **MUST reject when any queued command failed.** A driver that reports
     * per-command errors inside the reply — ioredis resolves with one
     * `[error, result]` tuple per command and does not reject, because `EXEC`
     * itself succeeded — has to be adapted here, or a refused write is handed
     * to the caller as a success, and a member stranded with no TTL.
     */
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
     * `beforeMs` is first clamped to the server's clock plus `skewMs`, that
     * clock read in the same atomic step as the write; a `beforeMs` behind it
     * is written as given.
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
     * Resolves with the stored value, exactly as written, and the server's
     * clock in epoch milliseconds, as read in that step.
     */
    advanceRevocationBoundaries(key: string, mode: "all" | "sessions", write: {
        readonly beforeMs: number;
        readonly expiresAtMs: number;
        readonly grantRetentionMs: number;
        readonly skewMs: number;
    }): Promise<{
        readonly value: string;
        readonly serverNowMs: number;
    }>;
    /**
     * What the server says about keeping what it is written, read once by the
     * store's factory for its eviction gate: a watermark evicted before its
     * expiry reads as no revocation.
     */
    durability(): Promise<RedisDurability>;
}
//# sourceMappingURL=user-sessions.d.mts.map