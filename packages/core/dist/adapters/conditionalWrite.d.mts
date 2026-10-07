declare const storeGenerationBrand: unique symbol;
/**
 * The generation a store issued for one record, or for one set's membership:
 * opaque, compared only with `===`. Fresh on every write of what it guards,
 * the create included, and never re-issued for its key (docs/adapter-surface.md,
 * "Conditional writes", rule 8): random, never a counter, a digest or a
 * timestamp. Only the store makes one; a caller only hands back one it was
 * given.
 */
export type StoreGeneration = string & {
    readonly [storeGenerationBrand]: true;
};
/**
 * Whether `value` is a generation a store may answer: 1 to 128 visible ASCII
 * characters (0x21–0x7e) other than `"`, so that `"<generation>"` is a strong
 * ETag. Never throws.
 */
export declare function isStoreGeneration(value: unknown): value is StoreGeneration;
/** A fresh generation: a random (v4) UUID. One way for a store that makes its own. */
export declare function newStoreGeneration(): StoreGeneration;
/**
 * The bundled stores' write-lifetime bound, 24 hours. A set reads absent only
 * once this has passed since its last membership write, and a
 * `createIf(…, null)` commits or fails within it of the read that answered
 * `null`. The bound is allocated: the adapter declares its write lifetime W
 * (issue to commit or failure), and the port's owning module issues a
 * conditional write only within (bound − W) of its read
 * (docs/adapter-surface.md, "Conditional writes", rule 6).
 */
export declare const BUNDLED_STORE_WRITE_LIFETIME_MS: number;
/** A stored record and the generation it was read at, from one snapshot. */
export interface Versioned<T> {
    readonly value: T;
    readonly generation: StoreGeneration;
}
/**
 * A set's members and the set's generation, from one snapshot. `generation`
 * is `null` only for an absent set: never written, or its tombstone expired.
 * A set emptied by any membership write (its last removal or a reset) keeps
 * its tombstone: it reads absent only once the store's write-lifetime bound
 * ({@link BUNDLED_STORE_WRITE_LIFETIME_MS} for the bundled stores) has passed
 * since its last membership write.
 */
export interface VersionedSet<T> {
    readonly items: readonly T[];
    readonly generation: StoreGeneration | null;
}
/**
 * A record-scoped replace, applied only while the record is at the expected
 * generation, as one atomic step in the store. It never creates a record.
 * - `updated`: written; `generation` is the record's new one.
 * - `missing`: no live record (absent, removed or past the store's retention).
 *   Nothing was written, and nothing was added to any listing.
 * - `conflict`: the record is live at another generation. Nothing was written.
 * A store that cannot tell rejects; it never answers `missing` for an outage.
 * A rejection after the request was sent means "unknown", never "not written".
 */
export type ConditionalReplaceAnswer = {
    readonly outcome: "updated";
    readonly generation: StoreGeneration;
} | {
    readonly outcome: "missing";
} | {
    readonly outcome: "conflict";
};
/** A record-scoped delete, applied only while the record is at the expected generation. The outcomes as for a replace. */
export type ConditionalRemoveAnswer = {
    readonly outcome: "removed";
} | {
    readonly outcome: "missing";
} | {
    readonly outcome: "conflict";
};
/**
 * Adding one member to a set, only while the set is at the expected
 * generation (`null`: only while the set is absent). Never `missing`.
 * `conflict` covers a set at another generation, a set absent where
 * `expected` names one, a set present where `expected` is `null`, and a
 * member id already held. Nothing is written on `conflict`.
 */
export type ConditionalCreateAnswer = {
    readonly outcome: "created";
    readonly generation: StoreGeneration;
} | {
    readonly outcome: "conflict";
};
/**
 * Removing one member of a set, only while the set is at the expected
 * generation. `removed` carries the set's new generation: the set stays,
 * even when it is now empty. `missing`: no set, or no such member at
 * `expected`, with nothing written and the generation unchanged.
 * `conflict`: the set is at another generation. The generation is checked
 * before the member.
 */
export type ConditionalSetRemoveAnswer = {
    readonly outcome: "removed";
    readonly generation: StoreGeneration;
} | {
    readonly outcome: "missing";
} | {
    readonly outcome: "conflict";
};
/** `answer[key]`, read once; a TypeError when `answer` is no object or the read throws. */
export declare const field: (answer: unknown, key: string, what: string) => unknown;
/** `answer.generation`, read once and required to be a well-formed generation. */
export declare const generationOf: (answer: unknown, what: string) => StoreGeneration;
/** `answer.outcome`, read once and required to be one of `outcomes`. */
export declare const outcomeOf: <O extends string>(answer: unknown, outcomes: readonly O[], what: string) => O;
/** A versioned read: `null` when the store holds no live record, else the value and its generation. */
export declare function readVersioned<T>(answer: Versioned<T> | null): Versioned<T> | null;
/**
 * `items` copied by one read of its length and one read of each index, so
 * neither an iterator nor a changing length decides what is copied.
 */
export declare const copyItems: <T>(items: readonly T[], what: string) => T[];
/**
 * A versioned set read: the items copied into a new frozen array, each item
 * the port's to judge. A `null` generation is an absent set's, so it holds
 * no items.
 */
export declare function readVersionedSet<T>(answer: VersionedSet<T>): VersionedSet<T>;
/** A conditional replace's answer. */
export declare function readConditionalReplaceAnswer(answer: unknown): ConditionalReplaceAnswer;
/** A record-scoped conditional remove's answer: the outcome alone. */
export declare function readConditionalRemoveAnswer(answer: unknown): ConditionalRemoveAnswer;
/** A conditional create's answer. */
export declare function readConditionalCreateAnswer(answer: unknown): ConditionalCreateAnswer;
/** A set-scoped conditional remove's answer: `removed` always with the set's new generation. */
export declare function readConditionalSetRemoveAnswer(answer: unknown): ConditionalSetRemoveAnswer;
export {};
//# sourceMappingURL=conditionalWrite.d.mts.map