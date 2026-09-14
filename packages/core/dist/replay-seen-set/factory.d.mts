import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { ReplaySeenSet } from "./types.mjs";
/**
 * Domain-specific AdapterFactory alias for ReplaySeenSet.
 * Per A1 §5.6.
 */
export type ReplaySeenSetFactory = AdapterFactory<ReplaySeenSet>;
export declare function createReplaySeenSetFactory(): ReplaySeenSetFactory;
export declare function registerBuiltinReplaySeenSets(factory: ReplaySeenSetFactory): void;
//# sourceMappingURL=factory.d.mts.map