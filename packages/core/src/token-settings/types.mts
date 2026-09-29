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
 * Nor is the token-binding dispatch policy (`oauth.tokenBinding.dispatch-policy`),
 * though it sits in `oauth {}` today: it arbitrates between the mechanisms
 * contributed to core's token-binding extension point, and the extension
 * point's owner, core, owns the policy (#728). Core reads it with its own
 * `resolveTokenBindingDispatchPolicy`, in every composition, and a slot that
 * carried it would be a second source for it; the contract refuses one that
 * does. Where the key lives is decided with the move of the configuration.
 *
 * Not every module can read the slot. The boot planner orders modules, not
 * components: a module that reads a key depends on the whole module providing
 * it. So no module in the oauth module's dependency set — the providers of its
 * `requires` and its `optional` keys, and whatever those depend on in turn —
 * can read this slot, because the oauth module would depend on it and it on
 * the oauth module, and boot refuses the pair as a cycle. Such a module reads
 * the configuration, as before: the default refresh-token family revocation
 * module is one, since the oauth module reads the `refreshTokenFamilyRevocation`
 * it provides. Providing the slot from a module that depends on none of them
 * would lift the constraint; that is left for later.
 *
 * Each value is resolved — no deprecated alias and no absence left for a
 * reader to interpret — and the whole is frozen, so a reader cannot change
 * what the others read. The contract suite and a test double are published
 * on `@o3co/auth-provider-core/testing` (`oauthTokenSettingsContract`,
 * `createTestOAuthTokenSettings`). Types only.
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
	/**
	 * `oauth.tokenBinding.bindConfidentialClientRefreshTokens`, `false` when
	 * unset: whether a grant binds a confidential client's refresh token to the
	 * key or certificate presented, as it always binds a public client's (#275).
	 */
	readonly bindConfidentialClientRefreshTokens: boolean;
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
