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
 * What other modules read of the oauth module's token settings, and the
 * `oauthTokenSettings` slot they read it through. Types only.
 *
 * A key several modules read has one owner (here the oauth module, owner of
 * `oauth {}`), which parses its section once and provides these values.
 * Most readers list the slot as optional, since they also run without the
 * oauth module, and read the configuration only when nothing fills it. A
 * reader that requires the slot reads none of the configuration: a
 * composition without the oauth module fills the slot itself. A
 * provided slot is read whole, checked with `checkOAuthTokenSettings`, never
 * mixed with the configuration.
 *
 * Not here:
 * - the grant-type allowlist switch: only the oauth module reads it;
 * - the revocation modes (`oauth.revocation.*`): the declared-absence guard
 *   reads them at validation, before any provider runs;
 * - `core.tokenBinding`: owned by core's token-binding extension point,
 *   read with `resolveTokenBindingSettings` and carried by core's own
 *   `tokenBindingSettings` slot; this slot carrying it would be a second
 *   source, which the contract refuses.
 *
 * A module in the oauth module's dependency set (providers of its `requires`
 * and `optional` keys, transitively) cannot read the slot: boot orders
 * modules, not components, so that would be a cycle. Such a module (e.g. the
 * default refresh-token family revocation module) reads the configuration.
 *
 * Every value is resolved (no deprecated alias or absence left to interpret)
 * and the whole is frozen. Contract suite: `oauthTokenSettingsContract` on
 * `@o3co/auth-provider-test-kit`. Test double: `createTestOAuthTokenSettings`
 * on `@o3co/auth-provider-core/testing`.
 */

import type { AccessTokenLifetime } from "../config/application.schema.mjs";

export interface OAuthTokenSettings {
	/**
	 * `oauth.jwt.issuer`: the deployment's canonical issuer, held to
	 * `checkCanonicalIssuer`. Every token's `iss`, and the origin every URL
	 * this provider builds for a browser is on.
	 */
	readonly issuer: string;
	/**
	 * The access-token lifetime as `resolveAccessTokenLifetime` reads
	 * `oauth.accessToken`: the seconds minted when a request asks for no
	 * particular lifetime, and the most a request may obtain.
	 */
	readonly accessTokenLifetime: AccessTokenLifetime;
	/** `oauth.refreshToken.expiresIn`, in seconds, as `resolveRefreshTokenLifetime` reads it. */
	readonly refreshTokenExpiresIn: number;
	/**
	 * `oauth.resourceIndicator.enabled`, `false` when unset: whether RFC 8707
	 * resource indicators decide a token's audience.
	 */
	readonly resourceIndicatorEnabled: boolean;
	/**
	 * `oauth.requireEmailVerified`, `false` when unset: whether tokens for an
	 * end-user subject require the Store to have verified the user's email.
	 */
	readonly requireEmailVerified: boolean;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** What other modules read of the oauth module's token settings, provided by the module that owns `oauth {}`. */
		readonly oauthTokenSettings?: OAuthTokenSettings;
	}
}
