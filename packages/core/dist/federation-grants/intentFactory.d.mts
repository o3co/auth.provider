import { type AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { FederationGrantIntentStore } from "./intentStore.mjs";
/** Domain-specific AdapterFactory alias for {@link FederationGrantIntentStore} (#593, slice 6). */
export type FederationGrantIntentStoreFactory = AdapterFactory<FederationGrantIntentStore>;
/**
 * Create an empty FederationGrantIntentStoreFactory. Consumers register their
 * own builders, or call {@link registerBuiltinFederationGrantIntentStores} for
 * the in-tree memory builder.
 */
export declare function createFederationGrantIntentStoreFactory(): FederationGrantIntentStoreFactory;
/**
 * Register the in-tree built-in builders. Currently `memory` alone, which warns
 * when it is BUILT and not when it is registered: registering is what a library
 * did, building is what a deployment did.
 *
 * @param logger - where the warning goes. Defaults to `consoleLogger`.
 */
export declare function registerBuiltinFederationGrantIntentStores(factory: FederationGrantIntentStoreFactory, logger?: Logger): void;
//# sourceMappingURL=intentFactory.d.mts.map