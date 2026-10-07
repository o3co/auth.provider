import type { Logger } from "../logging/Logger.mjs";
import { type AttemptCounter } from "./attempts.mjs";
export declare const DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES = 100000;
/** The least time between two `attempt_counter_evicted` warnings. */
export declare const ATTEMPT_COUNTER_EVICTION_WARN_INTERVAL_MS = 60000;
export interface MemoryAttemptCounterOptions {
    /** The most keys it holds a window for. Default {@link DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES}. */
    readonly maxEntries?: number;
    /** Epoch milliseconds. Default `Date.now`. */
    readonly now?: () => number;
    /** Where an eviction is reported. Default `consoleLogger`. */
    readonly logger?: Pick<Logger, "warn">;
    /** The `tag` on the eviction warning: what the counter counts for. */
    readonly tag?: string;
}
export declare function createMemoryAttemptCounter(options?: MemoryAttemptCounterOptions): AttemptCounter;
//# sourceMappingURL=attemptsMemory.d.mts.map