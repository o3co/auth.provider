import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { WebAuthnCredentialStore } from "./types.mjs";
/**
 * Domain-specific AdapterFactory alias for WebAuthnCredentialStore.
 * Follows the same pattern as AccessTokenDenylistFactory / ChallengeStoreFactory.
 */
export type WebAuthnCredentialStoreFactory = AdapterFactory<WebAuthnCredentialStore>;
/**
 * Create an empty WebAuthnCredentialStoreFactory. Consumers register their own
 * builders, or call registerBuiltinWebAuthnCredentialStores for the in-tree
 * memory builder.
 */
export declare function createWebAuthnCredentialStoreFactory(): WebAuthnCredentialStoreFactory;
/**
 * Register the in-tree built-in builders on a WebAuthnCredentialStoreFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export declare function registerBuiltinWebAuthnCredentialStores(factory: WebAuthnCredentialStoreFactory): void;
//# sourceMappingURL=factory.d.mts.map