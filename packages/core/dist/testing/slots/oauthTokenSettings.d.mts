/**
 * The test double of the `oauthTokenSettings` slot.
 * `createTestOAuthTokenSettings` answers the fixture configuration's
 * settings with members replaced; it checks nothing, so a test of a broken
 * value builds it here. The contract suite is
 * `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */
import type { AccessTokenLifetime } from "../../config/application.schema.mjs";
import type { OAuthTokenSettings } from "../../token-settings/types.mjs";
/** What a test replaces of the double's settings; a nested member is replaced member by member. */
export interface TestOAuthTokenSettingsOverrides {
    readonly issuer?: string;
    readonly accessTokenLifetime?: Partial<AccessTokenLifetime>;
    readonly refreshTokenExpiresIn?: number;
    readonly resourceIndicatorEnabled?: boolean;
    readonly requireEmailVerified?: boolean;
}
/**
 * The settings of the fixture configuration (`makeValidCoreConfig`),
 * resolved — its issuer, a 3600-second access token, a 86400-second
 * refresh token, every switch off — with
 * `overrides` applied, frozen all the way down.
 */
export declare function createTestOAuthTokenSettings(overrides?: TestOAuthTokenSettingsOverrides): OAuthTokenSettings;
//# sourceMappingURL=oauthTokenSettings.d.mts.map