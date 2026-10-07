import { type EventLogger, type MfaTransactionStore } from "@o3co/auth-provider-core";
import type { MfaTransactionStoreClient } from "./clients.mjs";
/** The key namespace `redisMfaTransactionStore.keyPrefix` defaults to. */
export declare const DEFAULT_REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX = "mfat:";
export interface RedisMfaTransactionStoreOptions {
    readonly client: MfaTransactionStoreClient;
    /** Outer namespace; each key's family and hash tag follow it. No brace. Default `mfat:`. */
    readonly keyPrefix?: string;
    /**
     * The clock a transaction expires by on this side, in epoch milliseconds:
     * `create` refuses an expiry at or before it, and a read answers a
     * transaction at or past its `expiresAtMs` on it as absent, whatever the
     * server's clock says. A session's proof is judged on it too; a subject's
     * first-binding mark is not (the server's clock decides it). Default
     * `Date.now`.
     */
    readonly now?: () => number;
    /**
     * Where a binding index step that failed after its operation answered is
     * warned (`mfa_transaction_evict_failed`, `mfa_transaction_unindex_failed`).
     * Default `consoleLogger`.
     */
    readonly logger?: Pick<EventLogger, "warn">;
}
/**
 * The Redis {@link MfaTransactionStore}. It resolves once the server's
 * eviction policy passes the gate (`internal/eviction-policy.mts`); an option
 * it cannot use rejects before the server is asked.
 */
export declare function createRedisMfaTransactionStore(options: RedisMfaTransactionStoreOptions): Promise<MfaTransactionStore>;
/**
 * `defineModule` manifest for the Redis {@link MfaTransactionStore}, off the
 * `mfaTransactionStoreClient` slot, keys under
 * `redis-mfa-transaction-store.keyPrefix` (`mfat:`), its own section (strict).
 * Declares no `replicaSafety`:
 * transactions, attempt limits and the lock are shared by every replica.
 *
 * The email-proof requirement must last as enrolled factors do. The store is
 * built by {@link createRedisMfaTransactionStore}, so a server that fails the
 * eviction gate refuses the boot (`mfa-transaction-store-evictable`); then
 * RDB without AOF (`mfa_transaction_store_lossy`), no persistence
 * (`mfa_transaction_store_volatile`) and a server refusing the persistence
 * questions (`mfa_transaction_store_durability_unchecked`) each warn on the
 * `logger` slot (or `consoleLogger`).
 */
export declare const redisMfaTransactionStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=mfa-transaction-store.d.mts.map