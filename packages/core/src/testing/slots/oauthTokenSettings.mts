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
export function createTestOAuthTokenSettings(
	overrides: TestOAuthTokenSettingsOverrides = {},
): OAuthTokenSettings {
	return Object.freeze({
		issuer: overrides.issuer ?? "https://auth.test",
		accessTokenLifetime: Object.freeze({
			defaultExpiresIn: overrides.accessTokenLifetime?.defaultExpiresIn ?? 3600,
			maxExpiresIn: overrides.accessTokenLifetime?.maxExpiresIn ?? 3600,
		}),
		refreshTokenExpiresIn: overrides.refreshTokenExpiresIn ?? 86_400,
		resourceIndicatorEnabled: overrides.resourceIndicatorEnabled ?? false,
		requireEmailVerified: overrides.requireEmailVerified ?? false,
	});
}
