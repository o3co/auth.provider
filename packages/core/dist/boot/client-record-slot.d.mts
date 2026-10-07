import type { ComponentKey } from "../modules/manifest/component-map.mjs";
/** What stage 3 does to the `clientRepository` slot. */
export interface ClientRecordSlot {
    /** Before any provider runs: puts the boundary over a host's value in the slot. */
    beforeProviders(): void;
    /** The value the working map holds for a provider's `value` under `key`. */
    provided(key: ComponentKey, value: unknown): unknown;
}
/**
 * Stage 3's handling of the `clientRepository` slot in `components`, the
 * working map. The slot holds the boundary over whatever fills it: a host's
 * value (bootstrap or override) before any provider runs, a provider's as it
 * is materialised. Every value but `null` and `undefined` is wrapped, a
 * callable or a primitive carrying the port's methods included, so nothing
 * that answers lookups reaches a reader around the boundary; an empty slot
 * stays empty, for stage 1's rules to have judged.
 *
 * - **One boundary.** A boundary already in the slot (one the host built
 *   with `validatedClientRepository`) is kept as it is, never wrapped twice,
 *   so it keeps its own logger; a reader that wraps the slot again gets the
 *   same object back.
 * - **The logger.** A refusal is warned through the `logger` component the
 *   map holds when the refusal happens, else `consoleLogger`.
 * - **Lifecycle.** Wrapping reads nothing of the value, so a value whose
 *   reads throw is installed as any other. A provider's cleanup is still
 *   handed its own value. Disposing the boundary disposes the value it wraps
 *   when that has a `Symbol.asyncDispose`, read at dispose, so boot's
 *   dispose reaches it as it would unwrapped; a host's value is still never
 *   disposed by boot.
 */
export declare function clientRecordSlotFor(components: Record<string, unknown>): ClientRecordSlot;
//# sourceMappingURL=client-record-slot.d.mts.map