/**
 * Provides the in-process {@link MfaFactorStore}. A restart loses every
 * enrollment; without the enrollment witness, whoever holds a password could
 * then bind their own authenticator, so the module warns once when built.
 */
export declare const memoryMfaFactorStoreModule: import("../modules/manifest/module-spec.mjs").Module;
/**
 * Provides the in-process {@link MfaTransactionStore}. A restart loses the
 * ceremonies in flight, lifts the subject lock state, and drops the email-proof
 * requirement an operator reset recorded, so beside a durable factor store a
 * password holder could then bind without the proof; the module warns once when
 * built. Capped at `core-mfa-transaction-store-memory.maxEntries`, its own
 * section (adapter default when unset); a value that is not a positive whole number refuses the
 * boot, naming the key. The section is strict; `mfaTransactionStore.memory`,
 * its old path, refuses boot naming it.
 */
export declare const memoryMfaTransactionStoreModule: import("../modules/manifest/module-spec.mjs").Module;
//# sourceMappingURL=module.d.mts.map