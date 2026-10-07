import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createMemoryAccessTokenDenylist } from "./memory.mjs";
/**
 * Create an empty AccessTokenDenylistFactory. Consumers register their own
 * builders, or call registerBuiltinAccessTokenDenylists for the in-tree memory
 * builder.
 */
export function createAccessTokenDenylistFactory() {
    return createAdapterFactory("AccessTokenDenylist");
}
/**
 * Register the in-tree built-in builders on an AccessTokenDenylistFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export function registerBuiltinAccessTokenDenylists(factory) {
    factory.register("memory", () => createMemoryAccessTokenDenylist());
}
