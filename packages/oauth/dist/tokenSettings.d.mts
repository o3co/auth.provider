/**
 * The oauth module's token settings as core's `OAuthTokenSettings` — the
 * `oauthTokenSettings` slot this module provides.
 *
 * A token cannot exist apart from OAuth, so these settings are this module's,
 * in `oauth {}`; modules outside this package that mint, bind or verify
 * tokens, or build a URL on the issuer, read them through the slot instead of
 * the section. Each value is resolved here, from the section alone:
 *
 * - the issuer as written, held to core's `checkCanonicalIssuer` — the oauth
 *   router refuses the same issuer at construction;
 * - the lifetimes through core's `resolveAccessTokenLifetime` and
 *   `resolveRefreshTokenLifetime`;
 * - every switch on only when it is `true`.
 *
 * The token-binding settings under `core.tokenBinding` are not among them:
 * they apply across core's token-binding extension point, so core reads them
 * itself (`resolveTokenBindingSettings`).
 *
 * Frozen, nested members too, so no reader can change what the others read.
 */
import { type OAuthTokenSettings } from "@o3co/auth-provider-core";
/**
 * The keys of `oauth {}` the settings are read from: the section as the
 * module's schema parsed it, or as a composition that provides the slot
 * without the module writes it.
 */
export interface OAuthTokenSection {
    readonly jwt?: {
        readonly issuer?: unknown;
    };
    readonly accessToken?: {
        readonly defaultExpiresIn?: unknown;
        readonly maxExpiresIn?: unknown;
    };
    readonly refreshToken?: {
        readonly expiresIn?: unknown;
    };
    readonly resourceIndicator?: {
        readonly enabled?: unknown;
    };
    readonly requireEmailVerified?: unknown;
}
/**
 * The token settings the section `oauth` carries, resolved and frozen. Throws
 * on an issuer that is not canonical, and on a lifetime core's resolvers
 * refuse.
 */
export declare function oauthTokenSettingsFrom(oauth: OAuthTokenSection | undefined): OAuthTokenSettings;
//# sourceMappingURL=tokenSettings.d.mts.map