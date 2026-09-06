import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { ChallengeStore } from "./types.mjs";
/**
 * Domain-specific AdapterFactory alias for ChallengeStore.
 *
 * Per A1 §5.6: register(type, builder) throws on duplicate; replace(type,
 * builder) is the explicit override path; NO freeze() method (composition-
 * root concern, not module registry).
 */
export type ChallengeStoreFactory = AdapterFactory<ChallengeStore>;
/**
 * Create an empty ChallengeStoreFactory. Consumers register their builders
 * (or call registerBuiltinChallengeStores for the in-tree memory builder).
 */
export declare function createChallengeStoreFactory(): ChallengeStoreFactory;
/**
 * Register the in-tree built-in builders on a ChallengeStoreFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export declare function registerBuiltinChallengeStores(factory: ChallengeStoreFactory): void;
//# sourceMappingURL=factory.d.mts.map