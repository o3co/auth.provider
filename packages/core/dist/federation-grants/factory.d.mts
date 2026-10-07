import { type AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { FederationGrantStore } from "./store.mjs";
/** Domain-specific AdapterFactory alias for {@link FederationGrantStore} (#593). */
export type FederationGrantStoreFactory = AdapterFactory<FederationGrantStore>;
/**
 * Create an empty FederationGrantStoreFactory. Consumers register their own
 * builders, or call {@link registerBuiltinFederationGrantStores} for the
 * in-tree memory builder.
 */
export declare function createFederationGrantStoreFactory(): FederationGrantStoreFactory;
/**
 * Register the in-tree built-in builders on a FederationGrantStoreFactory.
 * Currently that is `memory` alone, which warns when it is built, as the
 * session-bound token store's does: what it holds are refresh tokens good for
 * up to a year, in the clear, gone at the next restart.
 *
 * @param logger - where the warning goes. Defaults to `consoleLogger`.
 */
export declare function registerBuiltinFederationGrantStores(factory: FederationGrantStoreFactory, logger?: Logger): void;
//# sourceMappingURL=factory.d.mts.map