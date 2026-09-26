/** The most entries a V8 `Map` holds, and so the largest cap an in-process store takes. */
export declare const MAX_MEMORY_STORE_ENTRIES: number;
/**
 * Refuse a cap `owner` (a store's factory) cannot use: `${owner}: maxEntries
 * must be …`. Answers the cap.
 */
export declare function usableMaxEntries(maxEntries: number, owner: string): number;
/** The store's options for the value at `key`: `{}` when absent, `{ maxEntries }` when usable. */
export declare function configuredMaxEntries(value: unknown, key: string): {
    readonly maxEntries?: number;
};
//# sourceMappingURL=max-entries.d.mts.map