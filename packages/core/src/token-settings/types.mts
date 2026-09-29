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
 * `oauthTokenSettings` slot they read it through (#728).
 *
 * A token cannot exist apart from OAuth, so its settings belong to the oauth
 * module's section, `oauth {}`. A key several modules read has one owner, and
 * the others receive it through a slot whose contract is core's: the owner
 * parses its section once and provides these values, and a reader requires
 * the slot rather than reading the section. The members are what modules
 * outside `packages/oauth` read today. Two settings of the section are not
 * here: the grant-type allowlist switch, which only the oauth module reads,
 * and the revocation modes (`oauth.revocation.accessToken`,
 * `oauth.revocation.subject`). Those are the declarations core's
 * declared-absence guard reads for the absence policies `oauth-token-exchange`,
 * `session` and `webauthn` attach as well as oauth: the guard reads them at
 * validation, before any provider runs, so a slot cannot serve them, and
 * where they live once `oauth {}` is the oauth module's alone is decided
 * with that move.
 *
 * Each value is resolved — no deprecated alias and no absence left for a
 * reader to interpret — and the whole is frozen, so a reader cannot change
 * what the others read. The contract suite and a test double are published
 * on `@o3co/auth-provider-core/testing` (`oauthTokenSettingsContract`,
 * `createTestOAuthTokenSettings`). Types only.
 */

import type { AccessTokenLifetime } from "../config/application.schema.mjs";
import type { DispatchPolicy } from "../middleware/tokenBinding.mjs";

/** The settings that apply across every token-binding mechanism installed (DPoP, mTLS). */
export interface OAuthTokenBindingSettings {
	/**
	 * `oauth.tokenBinding.dispatch-policy`: how core's token-binding middleware
	 * arbitrates between the mechanisms contributed as `tokenBindingMechanisms`.
	 */
	readonly dispatchPolicy: DispatchPolicy;
	/**
	 * `oauth.tokenBinding.bindConfidentialClientRefreshTokens`, `false` when
	 * unset: whether a confidential client's refresh token is bound to the key
	 * or certificate presented, as a public client's always is (#275).
	 */
	readonly bindConfidentialClientRefreshTokens: boolean;
}

export interface OAuthTokenSettings {
	/**
	 * `oauth.jwt.issuer`: the deployment's canonical issuer, held to
	 * `checkCanonicalIssuer`. Every token's `iss`, and the origin every URL
	 * this provider builds for a browser is on.
	 */
	readonly issuer: string;
	/**
	 * `oauth.jwt.legacyTypAccept`, `false` when unset: whether verifying a
	 * token this provider issued accepts one with no `typ` header.
	 */
	readonly legacyTypAccept: boolean;
	/**
	 * The access-token lifetime as `resolveAccessTokenLifetime` reads
	 * `oauth.accessToken`: the seconds minted when a request asks for no
	 * particular lifetime, and the most a request may obtain.
	 */
	readonly accessTokenLifetime: AccessTokenLifetime;
	/** `oauth.refreshToken.expiresIn`, in seconds, as `resolveRefreshTokenLifetime` reads it. */
	readonly refreshTokenExpiresIn: number;
	readonly tokenBinding: OAuthTokenBindingSettings;
	/**
	 * `oauth.resourceIndicator.enabled`, `false` when unset: whether RFC 8707
	 * resource indicators decide a token's audience.
	 */
	readonly resourceIndicatorEnabled: boolean;
	/**
	 * `oauth.requireEmailVerified`, `false` when unset: whether tokens for an
	 * end-user subject require the Store to have verified the user's email
	 * (#297).
	 */
	readonly requireEmailVerified: boolean;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** What other modules read of the oauth module's token settings (#728), provided by the module that owns `oauth {}`. */
		readonly oauthTokenSettings?: OAuthTokenSettings;
	}
}
