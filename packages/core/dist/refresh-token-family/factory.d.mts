import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { RefreshTokenFamilyStore } from "./types.mjs";
/**
 * Domain-specific AdapterFactory alias for RefreshTokenFamilyStore.
 *
 * Per A3 §5.6: register(type, builder) throws on duplicate; replace(type,
 * builder) is the explicit override path; NO freeze() method (composition-
 * root concern, not module registry). A6+A7 registry policy.
 */
export type RefreshTokenFamilyStoreFactory = AdapterFactory<RefreshTokenFamilyStore>;
/**
 * Create an empty RefreshTokenFamilyStoreFactory. Consumers register
 * their builders (or call registerBuiltinRefreshTokenFamilyStores for the
 * in-tree memory builder).
 */
export declare function createRefreshTokenFamilyStoreFactory(): RefreshTokenFamilyStoreFactory;
/**
 * Register the in-tree built-in builders on a RefreshTokenFamilyStoreFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export declare function registerBuiltinRefreshTokenFamilyStores(factory: RefreshTokenFamilyStoreFactory): void;
//# sourceMappingURL=factory.d.mts.map