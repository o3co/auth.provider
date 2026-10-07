/**
 * How a typed answer carries what the route that logs it needs and the caller
 * must not see — the failure it was turned from (`failure`), the store errors
 * it does not stand for (`absorbed`), the connection a refusal is about
 * (`connection`) — as a property nothing enumerates. A spread, a
 * serialisation, or a response or audit event built from the answer never
 * carries what a store or an upstream put on an error; a reader that asks for
 * the field by name gets it. Used by the retrieval and by lodging.
 */
/** `value`, with `payload` attached under `key` and not enumerable; nothing is attached for none. */
export declare function carrying<T extends object>(value: T, key: "failure" | "absorbed" | "connection", payload: unknown): T;
/** `value`, carrying the failure it was turned from. */
export declare const carryingFailure: <T extends object>(value: T, failure: unknown) => T;
//# sourceMappingURL=carry.d.mts.map