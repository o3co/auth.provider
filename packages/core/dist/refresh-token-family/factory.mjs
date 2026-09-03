import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createMemoryRefreshTokenFamilyStore } from "./adapters/memory.mjs";
/**
 * Create an empty RefreshTokenFamilyStoreFactory. Consumers register
 * their builders (or call registerBuiltinRefreshTokenFamilyStores for the
 * in-tree memory builder).
 */
export function createRefreshTokenFamilyStoreFactory() {
    return createAdapterFactory("RefreshTokenFamilyStore");
}
/**
 * Register the in-tree built-in builders on a RefreshTokenFamilyStoreFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export function registerBuiltinRefreshTokenFamilyStores(factory) {
    factory.register("memory", () => createMemoryRefreshTokenFamilyStore());
}
