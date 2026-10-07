/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
import { checkCanonicalIssuer, describeIssuerRejection, resolveAccessTokenLifetime, resolveRefreshTokenLifetime, } from "@o3co/auth-provider-core";
/**
 * The token settings the section `oauth` carries, resolved and frozen. Throws
 * on an issuer that is not canonical, and on a lifetime core's resolvers
 * refuse.
 */
export function oauthTokenSettingsFrom(oauth) {
    const issuer = oauth?.jwt?.issuer;
    const rejection = checkCanonicalIssuer(issuer);
    if (rejection !== null) {
        throw new Error(`oauthTokenSettings: oauth.jwt.issuer ${describeIssuerRejection(rejection)}`);
    }
    // Core's resolvers read a configuration; the section is all they read of it.
    const config = { oauth: oauth ?? {} };
    const { defaultExpiresIn, maxExpiresIn } = resolveAccessTokenLifetime(config);
    return Object.freeze({
        // `checkCanonicalIssuer` answered null, which only a string satisfies.
        issuer: issuer,
        accessTokenLifetime: Object.freeze({ defaultExpiresIn, maxExpiresIn }),
        refreshTokenExpiresIn: resolveRefreshTokenLifetime(config),
        resourceIndicatorEnabled: oauth?.resourceIndicator?.enabled === true,
        requireEmailVerified: oauth?.requireEmailVerified === true,
    });
}
