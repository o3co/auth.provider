import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createMemoryWebAuthnCredentialStore } from "./memory.mjs";
/**
 * Create an empty WebAuthnCredentialStoreFactory. Consumers register their own
 * builders, or call registerBuiltinWebAuthnCredentialStores for the in-tree
 * memory builder.
 */
export function createWebAuthnCredentialStoreFactory() {
    return createAdapterFactory("WebAuthnCredentialStore");
}
/**
 * Register the in-tree built-in builders on a WebAuthnCredentialStoreFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export function registerBuiltinWebAuthnCredentialStores(factory) {
    factory.register("memory", () => createMemoryWebAuthnCredentialStore());
}
