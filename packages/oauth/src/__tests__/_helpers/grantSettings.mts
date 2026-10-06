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
 * The slots the oauth-authorization grants read their settings from, filled
 * from a configuration built by hand as a composition fills them: a test that
 * builds a grant directly states its settings as `oauth {}` and
 * `core.tokenBinding`, and hands the grant what the oauth module and core
 * would resolve from them.
 */

import {
	type OAuthTokenSettings,
	resolveTokenBindingSettings,
	type TokenBindingSettings,
} from "@o3co/auth-provider-core";
import { type OAuthTokenSection, oauthTokenSettingsFrom } from "#/tokenSettings.mjs";

/**
 * What a configuration that names none is given: a slot always carries an
 * issuer and both lifetimes, as the package's reference.conf and the
 * deployment's issuer fill them.
 */
const FIXTURE_ISSUER = "https://auth.test";
const FIXTURE_ACCESS_TOKEN = { defaultExpiresIn: 3600 };
const FIXTURE_REFRESH_TOKEN_EXPIRES_IN = 86_400;

/**
 * `oauthTokenSettings` as the oauth module resolves it from `config`'s
 * `oauth {}` (the fixture's issuer and lifetimes where it names none), and
 * `tokenBindingSettings` as core resolves it from `core.tokenBinding`.
 */
export function grantSettingsFrom(config: unknown): {
	readonly oauthTokenSettings: OAuthTokenSettings;
	readonly tokenBindingSettings: TokenBindingSettings;
} {
	const oauth = ((config as { oauth?: OAuthTokenSection } | undefined)?.oauth ?? {}) as Record<
		string,
		unknown
	> & {
		jwt?: Record<string, unknown>;
		accessToken?: Record<string, unknown>;
		refreshToken?: Record<string, unknown>;
	};
	return {
		oauthTokenSettings: oauthTokenSettingsFrom({
			...oauth,
			jwt: { ...oauth.jwt, issuer: oauth.jwt?.issuer ?? FIXTURE_ISSUER },
			accessToken: oauth.accessToken ?? FIXTURE_ACCESS_TOKEN,
			refreshToken: { expiresIn: FIXTURE_REFRESH_TOKEN_EXPIRES_IN, ...oauth.refreshToken },
		}),
		tokenBindingSettings: resolveTokenBindingSettings(config),
	};
}
