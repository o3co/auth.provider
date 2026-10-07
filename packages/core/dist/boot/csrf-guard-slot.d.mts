import type { ComponentKey } from "../modules/manifest/component-map.mjs";
/** What stage 3 does to the `csrfGuard` slot. */
export interface CsrfGuardSlot {
    /** Before any provider runs: replaces a host's value in the slot with its snapshot. */
    beforeProviders(): void;
    /** The value the working map holds for a provider's `value` under `key`. */
    provided(key: ComponentKey, value: unknown): unknown;
}
/**
 * Stage 3's handling of the `csrfGuard` slot in `components`, the working
 * map.
 *
 * - A host's value is replaced before any provider runs; one that breaks
 *   the contract is refused with the check's RangeError, naming the member.
 * - A provider's value is replaced as it is materialised; its refusal is the
 *   caller's to report, after its rollback, as a failed provider. A cleanup
 *   is still handed the provider's own value.
 * - An empty key stays empty, as `undefined` does: a slot left unfilled is
 *   stage 3's to judge against what requires it.
 */
export declare function csrfGuardSlotFor(components: Record<string, unknown>): CsrfGuardSlot;
//# sourceMappingURL=csrf-guard-slot.d.mts.map