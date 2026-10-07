/**
 * The test double of the `httpSettings` slot. `createTestHttpSettings`
 * trusts no forwarding hop and lets no origin read unless told otherwise;
 * it checks nothing. The contract suite is
 * `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */
import type { HttpSettings } from "../../deployment/types.mjs";
/** What a test replaces of the double's settings. */
export interface TestHttpSettingsOverrides {
    readonly trustProxy?: HttpSettings["trustProxy"];
    readonly allowedOrigins?: readonly string[];
}
/** No forwarding hop trusted and no origin allowed to read — unless `overrides` say otherwise — frozen. */
export declare function createTestHttpSettings(overrides?: TestHttpSettingsOverrides): HttpSettings;
//# sourceMappingURL=httpSettings.d.mts.map