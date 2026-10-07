import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createMemoryChallengeStore } from "./adapters/memory.mjs";
/**
 * Create an empty ChallengeStoreFactory. Consumers register their builders
 * (or call registerBuiltinChallengeStores for the in-tree memory builder).
 */
export function createChallengeStoreFactory() {
    return createAdapterFactory("ChallengeStore");
}
/**
 * Register the in-tree built-in builders on a ChallengeStoreFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export function registerBuiltinChallengeStores(factory) {
    factory.register("memory", () => createMemoryChallengeStore());
}
