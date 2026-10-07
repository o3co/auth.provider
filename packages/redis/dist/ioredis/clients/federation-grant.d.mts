/**
 * The federation grant store's client, over a connection a Cluster client can serve: every
 * write one script, the lock one `SET … NX PX`, the index read one `ZRANGE`.
 */
import type { Redis } from "ioredis";
import type { FederationGrantStoreClient } from "../../clients.mjs";
/**
 * The commands a federation grant store needs from its connection.
 *
 * Narrower than `Redis` on purpose: everything a write does happens inside a
 * script, and a listing's reads are routed one key at a time, so a Cluster
 * client satisfies this too — without widening the WATCH-based adapters in
 * {@link makeIoredisClients}, which a Cluster cannot serve.
 */
export interface FederationGrantRedisCommands {
    evalsha(sha: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
    eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
    zrange(key: string, start: number, stop: number): Promise<string[]>;
    set(key: string, value: string, expiryMode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
}
/**
 * The federation grant store's connection, separate from {@link makeIoredisClients} so that a
 * Cluster deployment can have one.
 */
export declare function makeIoredisFederationGrantStoreClient(io: FederationGrantRedisCommands | Redis): FederationGrantStoreClient;
//# sourceMappingURL=federation-grant.d.mts.map