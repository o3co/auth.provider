import { type AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { ConsentStore, PendingConsentStore } from "./types.mjs";
/** Domain-specific AdapterFactory alias for {@link ConsentStore} (#527). */
export type ConsentStoreFactory = AdapterFactory<ConsentStore>;
/**
 * Create an empty ConsentStoreFactory. Consumers register their own builders,
 * or call {@link registerBuiltinConsentStores} for the in-tree memory builder.
 */
export declare function createConsentStoreFactory(): ConsentStoreFactory;
/**
 * Register the in-tree built-in builders on a ConsentStoreFactory. Currently
 * registers "memory". Throws AdapterFactoryError reason "duplicate" if any
 * builtin name is already registered.
 */
export declare function registerBuiltinConsentStores(factory: ConsentStoreFactory): void;
/**
 * Domain-specific AdapterFactory alias for {@link PendingConsentStore} (#552).
 *
 * The sibling of {@link ConsentStoreFactory}, and wired with it: the consent
 * step needs both slots, and `createOAuthRouter` refuses a composition with one
 * and not the other. A factory for only the first led a composition that
 * followed the pattern straight into that refusal.
 */
export type PendingConsentStoreFactory = AdapterFactory<PendingConsentStore>;
/** Create an empty PendingConsentStoreFactory. */
export declare function createPendingConsentStoreFactory(): PendingConsentStoreFactory;
/**
 * Register the in-tree built-in builders on a PendingConsentStoreFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export declare function registerBuiltinPendingConsentStores(factory: PendingConsentStoreFactory): void;
//# sourceMappingURL=factory.d.mts.map