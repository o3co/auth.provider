import { type SessionLifecycleStore } from "./types.mjs";
export declare const DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_ENTRIES = 100000;
export declare const DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_PARTICIPANTS = 1000;
export interface InMemorySessionLifecycleStoreOptions {
    /** The most records it holds. Default {@link DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_ENTRIES}. */
    readonly maxEntries?: number;
    /** The most participants one record holds. Default {@link DEFAULT_MEMORY_SESSION_LIFECYCLE_MAX_PARTICIPANTS}. */
    readonly maxParticipants?: number;
    /** Epoch milliseconds. Default `Date.now`. */
    readonly now?: () => number;
}
export declare function createInMemorySessionLifecycleStore(options?: InMemorySessionLifecycleStoreOptions): SessionLifecycleStore;
//# sourceMappingURL=memory.d.mts.map