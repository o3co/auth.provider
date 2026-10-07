/**
 * The persistence notices both MFA store modules write at boot, once their
 * factory has passed the eviction gate (`eviction-policy.mts`). "Only a
 * subject with no record that may count opens a first binding" is only as
 * strong as the store: a restart without persistence empties a subject's
 * list, and whoever holds the password can then bind their own
 * authenticator. The email-proof requirement an operator reset records is
 * lost the same way. So:
 *
 * - RDB snapshots without AOF are one warning, no persistence at all another;
 * - what could not be read (a question the server refused, as many managed
 *   services refuse `CONFIG`, or answered without the value) is named in one
 *   warning that the check could not run, and the boot goes on;
 * - a server that cannot answer at all fails the boot, as any store outage at
 *   boot does.
 *
 * See the MFA ADR (2026-09-25-multi-factor-authentication), D12.
 */
import { type Logger } from "@o3co/auth-provider-core";
import type { RedisDurability } from "../clients.mjs";
import type { EvictableRefusal } from "./eviction-policy.mjs";
/** The two stores the check guards, by their slot. */
export type RedisMfaStoreSlot = "mfaFactorStore" | "mfaTransactionStore";
/** What each store's eviction gate says when it refuses a server. */
export declare const MFA_STORE_EVICTABLE: Readonly<{
    mfaFactorStore: EvictableRefusal<"mfa-factor-store-evictable">;
    mfaTransactionStore: EvictableRefusal<"mfa-transaction-store-evictable">;
}>;
/**
 * Writes each persistence warning that applies to what `durability` answers
 * once on `logger`, object-first: the persistence's, then the one naming
 * what could not be read (`unread`: `appendonly`, `save`).
 */
export declare function checkRedisMfaStorePersistence(store: RedisMfaStoreSlot, durability: () => Promise<RedisDurability>, logger: Logger): Promise<void>;
//# sourceMappingURL=mfa-durability.d.mts.map