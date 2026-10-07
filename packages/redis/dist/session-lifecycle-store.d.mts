/**
 * Redis-backed `SessionLifecycleStore`. A session's whole record — its state,
 * participants and pending close work — is one hash with one expiry
 * (`PEXPIREAT`): `expiresAt` plus `DEFAULT_CLOCK_SKEW_MS`, raised by the
 * closing commit to the later of that and the commit plus `retainMs`. The
 * record therefore lapses whole.
 *
 * Each record lives in one of {@link SESSION_LIFECYCLE_SHARDS} shards, chosen
 * by {@link sessionLifecycleShardOf}, and each shard has a closing index (a
 * sorted set of the sids of its closing records) under the same hash tag, so
 * on Redis Cluster a record and its shard's index share one slot. A closing
 * commit adds the sid to the index and the completion that closes the record
 * removes it, in the script that writes the record, so the index never misses
 * a closing record and judges nothing by a clock. `listClosing` merges the
 * shards' indexes in byte order, and checks each sid's record in its shard's
 * own step, removing any whose record is no longer closing (one that lapsed
 * while closing, say).
 *
 * Every write is refused at or after a deadline the adapter stamps at issue
 * (`internal/write-deadline.mts`), so it commits within W of its issue or
 * never. `open`, `join` and `completeIf` keep their answer under a replay key
 * of their own on the record's slot until the clock skew past that deadline,
 * so a copy the driver sends again answers as the first did and writes
 * nothing. A write answered `late`, or unanswered within the write timeout,
 * rejects with an unknown outcome. `beginClose` needs no replay key: a copy
 * that lands again finds the record closing or closed and writes nothing.
 * Every member runs as a script, on the primary.
 *
 * The store assumes acknowledged writes are not rolled back and
 * `noeviction`, which the factory holds the server to
 * (`internal/eviction-policy.mts`): an evicted active or closing record drops
 * a live session's fence or loses its pending work, an evicted replay key lets
 * a resent write apply again, and the closing index carries no TTL, so an
 * evicted index hides a closing record from the listing.
 */
import { type SessionLifecycleStore } from "@o3co/auth-provider-core";
import type { SessionLifecycleStoreClient } from "./clients.mjs";
/** The key namespace the store defaults to. */
export declare const DEFAULT_REDIS_SESSION_LIFECYCLE_KEY_PREFIX = "ss:lc:";
/** The most participants one record holds by default. */
export declare const DEFAULT_REDIS_SESSION_LIFECYCLE_MAX_PARTICIPANTS = 1000;
export interface RedisSessionLifecycleStoreOptions {
    readonly client: SessionLifecycleStoreClient;
    /** Outer namespace; the sid's hash tag follows it. Without a brace. Default `ss:lc:`. */
    readonly keyPrefix?: string;
    /** The most participants one record holds; a join past it rejects. Default 1000. */
    readonly maxParticipants?: number;
}
/**
 * How many shards the records and their closing indexes are spread over. A
 * constant of the key layout, not a setting: changing it moves every record
 * to another key. Sixteen spreads the store over up to sixteen Cluster
 * primaries, keeps each shard's index to a sixteenth of the closing sessions,
 * and keeps a listing to sixteen index reads per page.
 */
export declare const SESSION_LIFECYCLE_SHARDS = 16;
/**
 * The shard of `sid`: the 32-bit FNV-1a hash of its UTF-8 bytes, modulo
 * {@link SESSION_LIFECYCLE_SHARDS}.
 */
export declare function sessionLifecycleShardOf(sid: string): number;
/**
 * The Redis {@link SessionLifecycleStore}. It resolves once the server's
 * eviction policy passes the gate (`internal/eviction-policy.mts`); an option
 * it cannot use rejects before the server is asked.
 */
export declare function createRedisSessionLifecycleStore(options: RedisSessionLifecycleStoreOptions): Promise<SessionLifecycleStore>;
//# sourceMappingURL=session-lifecycle-store.d.mts.map