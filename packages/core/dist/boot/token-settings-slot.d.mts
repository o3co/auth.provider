/**
 * boot/token-settings-slot.mts: what boot does for the `oauthTokenSettings`
 * slot. Whatever fills it — a host's bootstrap or override value, or a
 * provider's — enters the component map as the snapshot
 * `checkOAuthTokenSettings` answers: held to the contract, and to the
 * lifetimes core resolves from the configuration, read once and frozen. So
 * every reader of the slot reads one value that was checked, and a reader
 * holding the slot alone need not hold it to the configuration again.
 */
import type { ComponentKey } from "../modules/manifest/component-map.mjs";
/** What stage 3 does to the `oauthTokenSettings` slot. */
export interface TokenSettingsSlot {
    /**
     * Before any provider runs: replaces a host's value in the slot with its
     * snapshot. The override's source wins when the override map carries the
     * key, as its value does.
     */
    beforeProviders(fromOverride: boolean): void;
    /** The value the working map holds for a provider's `value` under `key`. */
    provided(key: ComponentKey, value: unknown, module: string): unknown;
}
/**
 * Stage 3's handling of the `oauthTokenSettings` slot in `components`, the
 * working map, against `config`, the configuration stage 1 parsed.
 *
 * - A host's value is replaced before any provider runs. A lifetime beyond
 *   the configuration's is refused as a BootError; one stage 1 saw is
 *   already refused there, so this one is a value that answered stage 1
 *   differently. A value that breaks the contract is refused with the
 *   check's RangeError, naming the member.
 * - A provider's value is replaced as it is materialised; its refusal is
 *   the caller's to report, after its rollback (the RangeError as a failed
 *   provider, the BootError as it is). A cleanup is still handed the
 *   provider's own value.
 * - An empty key stays empty: a composition without the slot reads the
 *   configuration.
 */
export declare function tokenSettingsSlotFor(components: Record<string, unknown>, config: unknown): TokenSettingsSlot;
//# sourceMappingURL=token-settings-slot.d.mts.map