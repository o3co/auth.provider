/**
 * Redis {@link FederationGrantIntentStore} (#593, D16, slice 6): acquisition's
 * records, under one hash tag of their own.
 *
 * ```text
 * <prefix>{intents}:i:<handle>      HASH   the intent, its deadline, its pointers, and the marker a spent one leaves
 * <prefix>{intents}:c:<challenge>   HASH   the consent record and the browser it is answerable from
 * <prefix>{intents}:tx:<state>      HASH   the connect transaction and the connection it belongs to
 * <prefix>{intents}:r:<pair>        ZSET   one member per live first-time intent, scored by its deadline
 * ```
 *
 * **One tag, so one script can reach what it has to.** A script is given the
 * key it is routed by and derives the others — the consent an intent points at,
 * the transaction under a stored state — from the prefix. They are all in one
 * slot, which is what makes that legal on a Cluster, and what makes each
 * operation of the port one atomic step rather than two commands with a race
 * between them.
 *
 * **Nothing spans this keyspace and a grant's** (`<prefix>{<id>}:grant`). D16
 * says so, and it is why: supersession is settled by the grant's own
 * current-intent pointer, and core — not an adapter — orders the two writes an
 * acquisition makes.
 *
 * **The bound is an index, not a counter.** A number would have to be
 * decremented by whoever finished, and a flow that never came back would leave
 * it counted for ever. Members scored by their deadline are dropped by
 * `ZREMRANGEBYSCORE` on the SERVER's clock, so a place is released by the
 * passage of time; the index's own deadline is its last member's plus an
 * allowance, so it never expires under a reservation it still holds.
 *
 * **Two clocks.** What a caller is told is judged on the `now` it passes; what
 * is reclaimed is judged by Redis — the key TTLs, and the server time the
 * admission script reads. No script deletes a record because a caller's clock
 * says it has lapsed.
 */
import { type FederationGrantIntentStore } from "@o3co/auth-provider-core";
import type { FederationGrantIntentStoreClient } from "./clients.mjs";
/**
 * How long the bound's index outlives its last reservation. It is not a grace
 * period for the reservation itself — `ZREMRANGEBYSCORE` drops that on its
 * deadline — only insurance that the key holding the index does not expire
 * while a member is still in it.
 */
export declare const FEDERATION_GRANT_RESERVATION_ALLOWANCE_MS: number;
export interface RedisFederationGrantIntentStoreOptions {
    readonly client: FederationGrantIntentStoreClient;
    /** Outer namespace, shared with the grant store's. The `{intents}` tag follows it. Default `fg:`. */
    readonly keyPrefix?: string;
    /** See {@link FEDERATION_GRANT_RESERVATION_ALLOWANCE_MS}. */
    readonly reservationAllowanceMs?: number;
}
export declare function createRedisFederationGrantIntentStore(options: RedisFederationGrantIntentStoreOptions): FederationGrantIntentStore;
/** The options the adapter takes, from the configuration an operator wrote. */
export declare function resolveRedisFederationGrantIntentStoreOptions(rawConfig: unknown): Omit<RedisFederationGrantIntentStoreOptions, "client">;
/**
 * `defineModule` manifest for the Redis federation grant intent store (#593,
 * D16, slice 6). Its own module, beside the grant store's, because a
 * deployment may keep grants in Redis and acquisition in memory on a single
 * replica — losing flows in progress on a restart and nothing else — and the
 * two are installed independently. The client is the composition root's to
 * provide, as the grant store's is; it may be the same connection.
 */
export declare const redisFederationGrantIntentStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=federation-grant-intent-store.d.mts.map