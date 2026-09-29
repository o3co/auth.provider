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
 * `oauthTokenSettings` slot this module provides (#728).
 *
 * A token cannot exist apart from OAuth, so these settings are this module's,
 * in `oauth {}`; the modules outside this package that mint, bind or verify
 * tokens, or build a URL on the issuer, read them through the slot instead of
 * reading the section. Each value is resolved here the way its readers
 * resolved it for themselves:
 *
 * - the issuer as written, held to core's `checkCanonicalIssuer` — the oauth
 *   router refuses the same issuer at construction;
 * - the lifetimes through core's `resolveAccessTokenLifetime` (the
 *   deprecated `expiresIn` read in its place) and `resolveRefreshTokenLifetime`;
 * - the dispatch policy through core's `resolveTokenBindingDispatchPolicy`,
 *   the one reading of `oauth.tokenBinding.dispatch-policy`, which boot reads
 *   through in a composition without this module;
 * - every switch on only when it is `true`.
 *
 * The whole is frozen, the nested members too, so no reader can change what
 * the others read.
 */

import {
	type AppConfig,
	checkCanonicalIssuer,
	describeIssuerRejection,
	type OAuthTokenSettings,
	resolveAccessTokenLifetime,
	resolveRefreshTokenLifetime,
	resolveTokenBindingDispatchPolicy,
} from "@o3co/auth-provider-core";

/** The keys of `oauth {}` the settings are read from, as a configuration may carry them. */
interface OAuthTokenSection {
	readonly jwt?: { readonly issuer?: unknown; readonly legacyTypAccept?: unknown };
	readonly tokenBinding?: { readonly bindConfidentialClientRefreshTokens?: unknown };
	readonly resourceIndicator?: { readonly enabled?: unknown };
	readonly requireEmailVerified?: unknown;
}

/**
 * The token settings `config` carries, resolved and frozen. Throws on an issuer
 * that is not canonical, and on a lifetime core's resolvers refuse.
 */
export function oauthTokenSettingsFrom(config: AppConfig): OAuthTokenSettings {
	const oauth = (config as { oauth?: OAuthTokenSection }).oauth;
	const issuer = oauth?.jwt?.issuer;
	const rejection = checkCanonicalIssuer(issuer);
	if (rejection !== null) {
		throw new Error(`oauthTokenSettings: oauth.jwt.issuer ${describeIssuerRejection(rejection)}`);
	}
	const { defaultExpiresIn, maxExpiresIn } = resolveAccessTokenLifetime(config);
	return Object.freeze({
		// `checkCanonicalIssuer` answered null, which only a string satisfies.
		issuer: issuer as string,
		legacyTypAccept: oauth?.jwt?.legacyTypAccept === true,
		accessTokenLifetime: Object.freeze({ defaultExpiresIn, maxExpiresIn }),
		refreshTokenExpiresIn: resolveRefreshTokenLifetime(config),
		tokenBinding: Object.freeze({
			dispatchPolicy: resolveTokenBindingDispatchPolicy(config),
			bindConfidentialClientRefreshTokens:
				oauth?.tokenBinding?.bindConfidentialClientRefreshTokens === true,
		}),
		resourceIndicatorEnabled: oauth?.resourceIndicator?.enabled === true,
		requireEmailVerified: oauth?.requireEmailVerified === true,
	});
}
