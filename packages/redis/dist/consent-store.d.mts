/**
 * Redis-backed `ConsentStore` and `PendingConsentStore` (#561) — what lets
 * the consent step for clients that are not first-party run under
 * `deployment.mode = "multi"`.
 *
 * The memory module is refused there, correctly: a consent granted on one
 * replica is asked for again on every other, and a request parked under a
 * challenge on one replica is unknown to the replica that receives the
 * answer. These adapters put both where every replica reads them. They are
 * provided together by one module, as the memory ones are: the consent step
 * needs both slots, and `createOAuthRouter` refuses a composition with one
 * and not the other.
 *
 * ### Keys
 *
 *     <keyPrefix>rec:<len>:<sub>|<len>:<clientId>   HASH   a consent record
 *     <keyPrefix>{pending}:ch:<challenge>           HASH   a parked request
 *     <keyPrefix>{pending}:sess:<sessionId>         ZSET   that session's challenges
 *
 * A consent record is one key, and every script over it touches that key
 * alone, so it needs no hash tag and its records spread across a Cluster.
 * The pair is encoded with length prefixes — the form the challenge and
 * replay stores use — because a subject or a client id may contain any
 * separator: `("a|b", "c")` and `("a", "b|c")` must not share a record.
 *
 * A parked request and its session's index are two keys, and `consume`
 * arrives with the challenge alone: it reaches the index through the record,
 * and `set` reaches the session's other requests through the index. Redis
 * Cluster runs a script in one slot, so the constant `{pending}` hash tag
 * puts them all there — at the cost of concentrating every parked request on
 * one slot, the trade `redisDeviceCodeStoreModule` makes with `{devauth}`
 * and for the same reason: a human-paced ceremony, bounded per session and
 * gone in minutes, not per-request traffic. The challenge and the session id
 * each follow a fixed segment of their own, after the tag, so neither can
 * spell the other's key or move the tag.
 *
 * ### Expiry is the timestamp; the TTL is a safety net
 *
 * Both records carry their own `expiresAt`, and every read compares it with
 * the caller's `Date.now()` — the port's contract is the timestamp, as it is
 * for `DeviceCodeStore`. The key TTL a write sets only reclaims records
 * nobody reads again (an abandoned consent page, a consent that lapsed
 * unasked), and it runs {@link CONSENT_EXPIRY_SLACK_MS} past the logical
 * expiry, so it never fires first. A consent recorded until revoked carries
 * no TTL at all — including when an earlier grant for the pair had one.
 *
 * ### The per-session bound
 *
 * `PENDING_CONSENT_PER_SESSION_LIMIT`, held in the script that parks a
 * request, through the session's index: expired requests leave first, then
 * the first-parked go until there is room — the memory adapter's rule, which
 * the shared contract suite checks for both.
 *
 * ### Corrupt records
 *
 * A stored value that is not the shape the port declares reads as absent, never
 * as a throw or a half-typed record — see "Reading what Redis hands back"
 * below for why absence, not an outage.
 */
import { type AdapterBuilder, type ConsentStore, type PendingConsentStore } from "@o3co/auth-provider-core";
import type { ConsentStoreClient, PendingConsentStoreClient } from "./clients.mjs";
/**
 * How far past a record's `expiresAt` its key's TTL runs: five minutes.
 *
 * The TTL is measured from the write on the Redis server's clock; the expiry
 * is judged on the clock of whichever replica reads next. A reader running
 * behind the writer still holds the record live after the TTL — measured by
 * the writer — has run out, so without slack a skewed replica would find a
 * live consent missing (the user asked again) or an open consent page's
 * request gone. Both fail closed, but both are visible to a user who did
 * nothing wrong.
 *
 * Five minutes is the allowance `verifyJwt` grants for clock skew between
 * hosts by default (`clockSkewMs`), so a fleet whose clocks that verifier
 * tolerates is one this store tolerates too. Nothing is decided by the slack
 * — expiry is still the timestamp — so erring long costs only the memory of
 * an abandoned record for five more minutes; erring short costs a user.
 */
export declare const CONSENT_EXPIRY_SLACK_MS: number;
/** Options for {@link createRedisConsentStore}. */
export interface RedisConsentStoreOptions {
    readonly client: ConsentStoreClient;
    /** Outer namespace; the `rec:` segment follows it. */
    readonly keyPrefix: string;
}
export declare function createRedisConsentStore(opts: RedisConsentStoreOptions): ConsentStore;
/** Options for {@link createRedisPendingConsentStore}. */
export interface RedisPendingConsentStoreOptions {
    readonly client: PendingConsentStoreClient;
    /** Outer namespace; the `{pending}` hash tag and the `ch:` / `sess:` segments follow it. */
    readonly keyPrefix: string;
}
export declare function createRedisPendingConsentStore(opts: RedisPendingConsentStoreOptions): PendingConsentStore;
/**
 * AdapterFactory builder for the Redis `ConsentStore` (composition pattern
 * §8.4). Register it next to {@link redisPendingConsentStoreBuilder}: the
 * consent step needs both slots, and `createOAuthRouter` refuses a
 * composition with one and not the other.
 *
 *   consentFactory.register("redis", redisConsentStoreBuilder);
 *   consentFactory.create({ type: "redis", client, keyPrefix: "consent:" });
 */
export declare const redisConsentStoreBuilder: AdapterBuilder<ConsentStore>;
/**
 * AdapterFactory builder for the Redis `PendingConsentStore` — the sibling of
 * {@link redisConsentStoreBuilder}, with the same default namespace.
 */
export declare const redisPendingConsentStoreBuilder: AdapterBuilder<PendingConsentStore>;
/**
 * `defineModule` manifest providing both consent slots off the shared Redis
 * clients — the counterpart of core's `memoryConsentStoreModule`, one switch
 * for one feature.
 *
 * Declares no `replicaSafety`, which is the point: a composition wiring the
 * consent step with this module may declare `deployment.mode = "multi"`. The
 * `consentStoreClient` and `pendingConsentStoreClient` slots it requires come
 * from `makeIoredisClients` (or the standalone's shared clients module).
 *
 * configSchema: top-level key `redisConsentStore` (module-namespaced per
 * master roadmap §3.5 — NO bare `keyPrefix` top-level key).
 */
export declare const redisConsentStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=consent-store.d.mts.map