import { type AdapterBuilder, type FederationTokenStoreBase, type SupportsLock } from "@o3co/auth-provider-core";
import type { FederationTokenStoreClient } from "./clients.mjs";
export type EncryptionConfig = {
    mode: "required";
    key: Buffer;
} | {
    mode: "allow-plaintext";
};
export interface RedisFederationTokenStoreOptions {
    client: FederationTokenStoreClient;
    encryption: EncryptionConfig;
    keyPrefix?: string;
    /**
     * Redis key TTL in seconds. This is the upper bound on how long a federation
     * token record persists; it MUST exceed the upstream federation refresh_token
     * lifetime so that refresh flows (F-6) can still retrieve the refresh_token
     * after the access_token has expired.
     *
     * Do NOT tie this TTL to `tokens.expiresAt` (the access_token expiry) —
     * access_token expiry is kept inside the envelope for F-6 to consult at
     * retrieval time, but the record itself lives until this store TTL elapses.
     *
     * Default: 86400 seconds (24 hours). Spec Section 5.2.
     */
    ttl?: number;
}
export declare function createRedisFederationTokenStore(opts: RedisFederationTokenStoreOptions): FederationTokenStoreBase & SupportsLock;
/**
 * AdapterFactory builder. Consumer wires:
 *   factory.register("redis", redisFederationTokenStoreBuilder);
 *
 * `config` shape:
 *   { client: FederationTokenStoreClient,
 *     encryption: EncryptionConfig | { mode?: "required" | "allow-plaintext", key?: Buffer | string },
 *     keyPrefix?: string,
 *     ttl?: number }
 *
 * Encryption defaults: mode = "required", key MUST be 32-byte (raw Buffer or
 * base64 string). `mode = "allow-plaintext"` emits a startup warning and is
 * intended for dev/test only (per spec §5).
 */
export declare const redisFederationTokenStoreBuilder: AdapterBuilder<FederationTokenStoreBase>;
/**
 * `defineModule` manifest for the redis FederationTokenStore. Static
 * composition path; for runtime-config-driven backend selection use the
 * builder above with the AdapterFactory pattern.
 *
 * configSchema: top-level key `redisFederationTokenStore` (module-namespaced
 * per master roadmap §3.5).
 *
 * `requires`: needs `federationTokenStoreClient` (per-purpose slot declared
 * in `@o3co/auth-provider-core`'s `federation-tokens/types.mts`) and
 * `config`. Encryption key is read from
 * `redisFederationTokenStore.encryptionKey` (base64 string) — operators set
 * it via env var `REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY`.
 */
export declare const redisFederationTokenStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=federation-tokens.d.mts.map