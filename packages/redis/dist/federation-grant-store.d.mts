import { type FederationGrantStore } from "@o3co/auth-provider-core";
import type { FederationGrantStoreClient } from "./clients.mjs";
import { type FederationGrantKey } from "./internal/crypto.mjs";
import { type EncryptionGuardContext } from "./internal/encryption-mode.mjs";
/**
 * How far past a record's horizon the subject index keeps its member, and how
 * far past the last horizon the index key itself lives: five minutes.
 *
 * The index is a key of its own, in its own slot, so on a Cluster it and the
 * records it points at are on different nodes, reading different clocks. A
 * member dropped while a replica whose clock is behind can still read its
 * record is a record `find` answers for and a listing has lost, so the drop
 * is held back by more than any two nodes in one deployment should disagree.
 * Erring the other way costs a dangling member until the next prune, which is
 * what the layout tolerates by design (D16).
 */
export declare const DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS = 300000;
export type { FederationGrantKey };
export type FederationGrantEncryption = {
    readonly mode: "required";
    readonly keys: readonly FederationGrantKey[];
} | {
    readonly mode: "allow-plaintext";
};
export interface RedisFederationGrantStoreOptions {
    readonly client: FederationGrantStoreClient;
    /** Outer namespace. The hash tag and the `:grant` / `:cred` / `:lock` segments follow it. Default `fg:`. */
    readonly keyPrefix?: string;
    /**
     * How long a record answers past the end of what it was authorized for
     * (D16). Taken at creation and kept with the record: a key's TTL and an
     * index score are set when they are written, so a store reopened under a
     * different setting must not disagree with the arithmetic it wrote.
     */
    readonly tombstoneRetentionMs?: number;
    readonly encryption: FederationGrantEncryption;
    /** See {@link DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS}. */
    readonly listingAllowanceMs?: number;
    /** What the production guard on `allow-plaintext` reads beside the mode (#473). */
    readonly guard?: EncryptionGuardContext;
}
/**
 * The Redis adapter for {@link FederationGrantStore} (#593, D16).
 *
 * Every write is one script and every guard is inside it; this module builds
 * the keys, seals and opens the credential, and derives the record. What it
 * never does is decide a write from a record it read a round trip earlier: a
 * read before a write is preparation — the subject an index is named after,
 * the authorization a credential is sealed under — and the script checks
 * every state it depends on again.
 */
export declare function createRedisFederationGrantStore(options: RedisFederationGrantStoreOptions): FederationGrantStore;
/** What a composition root tells the module that its configuration cannot (#473). */
export interface RedisFederationGrantStoreModuleOptions {
    /** The environment the configuration was selected by, when the root knows it by another name than `NODE_ENV`. */
    readonly environment?: string;
}
/**
 * The options the adapter takes, from the configuration an operator wrote.
 *
 * A function of its own, and exported, because the conversion is where a
 * module goes wrong silently: seconds forwarded as milliseconds keep a
 * tombstone for thirty seconds instead of thirty days, and a `0` read as
 * "unset" gives a deployment that wanted no tombstones the default thirty
 * days of them.
 */
export declare function resolveRedisFederationGrantStoreOptions(rawConfig: unknown, moduleOptions: RedisFederationGrantStoreModuleOptions): Omit<RedisFederationGrantStoreOptions, "client">;
/**
 * `defineModule` manifest for the Redis federation grant store (#593, D16).
 *
 * Its own module, and not a branch of the route package's, because the store
 * is what a deployment installs whether or not it mounts the routes —
 * `revokeAllForSubject` and a logout reach grants through the port.
 *
 * The plaintext guard reads `deployment.mode` off the configuration and the
 * selected environment off `options`, for the reason the federation-token
 * store's does: the module cannot know how a composition root chose its
 * configuration file.
 */
export declare function redisFederationGrantStoreModuleFor(options?: RedisFederationGrantStoreModuleOptions): import("@o3co/auth-provider-core").Module;
/**
 * The module with no environment named: the plaintext guard reads `NODE_ENV`
 * and `deployment.mode` (#473). A composition root that selects its
 * configuration by another name builds its own with
 * {@link redisFederationGrantStoreModuleFor}.
 */
export declare const redisFederationGrantStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=federation-grant-store.d.mts.map