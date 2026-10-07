/**
 * The test double of the `tokenBindingSettings` slot:
 * `createTestTokenBindingSettings` answers what an unset `core.tokenBinding`
 * reads as unless told otherwise; it checks nothing.
 */
import type { TokenBindingSettings } from "../../middleware/tokenBinding.mjs";
/** The intent-explicit policy and no confidential-client binding — unless `overrides` say otherwise — frozen. */
export declare function createTestTokenBindingSettings(overrides?: Partial<TokenBindingSettings>): TokenBindingSettings;
//# sourceMappingURL=tokenBindingSettings.d.mts.map