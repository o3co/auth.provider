/**
 * Redis-backed `DeviceCodeStore` (#433) — what lets the device grant run
 * under `deployment.mode = "multi"`.
 *
 * The in-memory store is refused there, correctly: pending authorizations
 * fork per replica, so the human approves a code on the replica that served
 * the verification page while the device polls one that has never heard of
 * it and is told the code does not exist. This adapter puts the record where
 * every replica reads it, and keeps the port's atomicity by making each
 * operation one Lua script — see `DeviceCodeStoreClient` for what each must
 * guarantee and `makeIoredisClients` for the scripts.
 *
 * ### Two keys, one slot
 *
 *     <keyPrefix>{devauth}:code:<device_code>   HASH    the record
 *     <keyPrefix>{devauth}:user:<user_code>     STRING  the device code
 *
 * The record is keyed by the device code and `approve`/`deny` arrive with the
 * user code, so there is an index — and a script that follows the index to
 * the record touches two keys derived from two independent random values.
 * Redis Cluster runs a script in one slot, so the pair has to hash together.
 * The constant `{devauth}` hash tag does that, at the cost of concentrating
 * every device authorization on one slot. For this flow's volume — a
 * human-initiated ceremony, not per-request traffic — that is an acceptable
 * trade, but it is a real one, which is why it is written here rather than
 * discovered later. The alternative, storing the record twice under each key,
 * would make `approve` and `poll` non-atomic across the pair: precisely what
 * the port forbids.
 *
 * ### TTL versus `expiresAtMs`
 *
 * Both keys carry the authorization's own expiry as an absolute deadline, so
 * expired records are reclaimed by Redis rather than swept. But the port's
 * contract is the timestamp, not the TTL: `poll` answers `expired` for a
 * record still inside its TTL whose `expiresAtMs` has passed on the caller's
 * clock, and drops it — the conformance suite checks that boundary. The TTL
 * is the safety net for a record nobody asks about again, not the source of
 * truth.
 *
 * ### The record
 *
 * One hash per authorization, every field a string; the scope lists are JSON
 * arrays so a scope value is stored byte-for-byte. A hash rather than a JSON
 * document so the scripts mutate fields in place — `status`, the grown
 * `intervalSeconds`, `lastPolledAtMs` — without re-encoding the whole thing,
 * and without `cjson`'s habit of turning an empty array into an object on
 * the way back out.
 */
import { type AdapterBuilder, type DeviceCodeStore } from "@o3co/auth-provider-core";
import type { DeviceCodeStoreClient } from "./clients.mjs";
/**
 * Options for createRedisDeviceCodeStore.
 */
export interface RedisDeviceCodeStoreOptions {
    readonly client: DeviceCodeStoreClient;
    /** Outer namespace; the `{devauth}` hash tag and the `code:`/`user:` segments follow it. */
    readonly keyPrefix: string;
}
export declare function createRedisDeviceCodeStore(opts: RedisDeviceCodeStoreOptions): DeviceCodeStore;
/**
 * AdapterFactory builder for runtime-config-driven backend selection
 * (composition pattern §8.4). Consumer registers via:
 *   factory.register("redis", redisDeviceCodeStoreBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "devauth:" });
 */
export declare const redisDeviceCodeStoreBuilder: AdapterBuilder<DeviceCodeStore>;
/**
 * `defineModule` manifest for the Redis DeviceCodeStore. Static composition
 * path (§8.1). For runtime-config-driven selection use the builder above.
 *
 * Declares no `replicaSafety`, which is the point: a composition
 * that mounts `deviceGrantModule` with this store may declare
 * `deployment.mode = "multi"`. The `deviceCodeStoreClient` slot it requires
 * comes from `makeIoredisClients` (or the standalone's shared clients module).
 *
 * configSchema: top-level key `redisDeviceCodeStore` (module-namespaced per
 * master roadmap §3.5 — NO bare `keyPrefix` top-level key).
 */
export declare const redisDeviceCodeStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=device-code-store.d.mts.map