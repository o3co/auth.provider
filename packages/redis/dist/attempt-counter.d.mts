/**
 * Redis-backed `AttemptCounter`: one atomic script per attempt
 * (`AttemptCounterClient.consume`), a hash per key under `<keyPrefix><key>`
 * holding the window's count and end.
 *
 * Its own key namespace: its keys share the `<tag>:<id>` form of the rate
 * limiter's, which keys them bare, and a shared server must never count an
 * attempt in a limiter's counter or the reverse.
 *
 * Clocks. A window's end is set on this side's clock (`now`), the one the
 * attempt guard reads the count on, and its key's TTL is relative: the
 * window's length plus `ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS`. A window is running
 * while its end is after `now` or its TTL is above the allowance, so neither a
 * server's clock set apart nor a replica's running ahead ends one early. A
 * replica ahead past the window's end is answered that end, which the guard
 * takes within the allowance and answers `503` beyond it. A forward step of
 * the server's wall clock still expires windows early, as for every TTL.
 *
 * A reply that is no count under the spec (`readAttemptCount`) rejects, as an
 * unreachable server does: the guard answers either as an outage.
 *
 * The factory refuses a server whose `maxmemory-policy` is not `noeviction`
 * (`internal/eviction-policy.mts`): every window's key carries a TTL, so any
 * evicting policy may drop a running window, and its key would start a fresh
 * one, loosening a verifier's limit.
 */
import { type AttemptCounter } from "@o3co/auth-provider-core";
import type { AttemptCounterClient } from "./clients.mjs";
/** The key namespace a counter given none keys its windows under. */
export declare const DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX = "attempt:";
export interface RedisAttemptCounterOptions {
    readonly client: AttemptCounterClient;
    /** Default {@link DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX}. */
    readonly keyPrefix?: string;
    /** Epoch milliseconds. Default `Date.now`. */
    readonly now?: () => number;
}
/**
 * The Redis {@link AttemptCounter}. It resolves once the server's eviction
 * policy passes the gate (`internal/eviction-policy.mts`); an option it
 * cannot use rejects before the server is asked.
 */
export declare function createRedisAttemptCounter(options: RedisAttemptCounterOptions): Promise<AttemptCounter>;
/**
 * `defineModule` manifest for the Redis `AttemptCounter`, filling the
 * `attemptCounter` slot. Its section, `redis-attempt-counter`, holds
 * `keyPrefix` (strict); the client comes from the `attemptCounterClient` slot.
 * The counter is built by {@link createRedisAttemptCounter}, so a server that
 * fails the eviction gate refuses the boot.
 */
export declare const redisAttemptCounterModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=attempt-counter.d.mts.map