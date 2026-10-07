import type { FederationGrantIntentStoreClient } from "../../clients.mjs";
/** What the intent scripts need of a connection: the script calls, and nothing else. */
export interface FederationGrantIntentRedisCommands {
    evalsha(sha: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
    eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
    hmget(key: string, ...fields: string[]): Promise<(string | null)[]>;
    exists(key: string): Promise<number>;
}
/**
 * The federation grant intent store's connection. It may be the grant store's own: nothing
 * here needs a second one, and the keys live under a different hash tag either way.
 */
export declare function makeIoredisFederationGrantIntentStoreClient(io: FederationGrantIntentRedisCommands): FederationGrantIntentStoreClient;
//# sourceMappingURL=federation-grant-intent.d.mts.map