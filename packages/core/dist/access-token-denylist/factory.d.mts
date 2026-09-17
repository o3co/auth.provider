import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { AccessTokenDenylist } from "./types.mjs";
/**
 * Domain-specific AdapterFactory alias for AccessTokenDenylist.
 * Relocated from types.mts to factory.mts per sibling pattern
 * (ChallengeStore / ReplaySeenSet / RefreshTokenFamilyStore).
 */
export type AccessTokenDenylistFactory = AdapterFactory<AccessTokenDenylist>;
/**
 * Create an empty AccessTokenDenylistFactory. Consumers register their own
 * builders, or call registerBuiltinAccessTokenDenylists for the in-tree memory
 * builder.
 */
export declare function createAccessTokenDenylistFactory(): AccessTokenDenylistFactory;
/**
 * Register the in-tree built-in builders on an AccessTokenDenylistFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export declare function registerBuiltinAccessTokenDenylists(factory: AccessTokenDenylistFactory): void;
//# sourceMappingURL=factory.d.mts.map