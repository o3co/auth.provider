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
 * The contract suite of the `oauthTokenSettings` slot.
 * `oauthTokenSettingsContract(input)` holds the settings to what the
 * configuration schema holds `oauth {}` to, resolved; token-binding
 * settings are core's, never the slot's. The slot's test double,
 * `createTestOAuthTokenSettings`, is core's, on its testing entry.
 */

import assert from "node:assert/strict";
import {
	checkCanonicalIssuer,
	describeIssuerRejection,
	isLifetimeSeconds,
	type OAuthTokenSettings,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "@o3co/auth-provider-core/testing";
import { unfrozenPath } from "../unfrozenPath.mjs";

export interface OAuthTokenSettingsContractInput {
	/** The settings under test, built afresh for each case: a provider's, over the configuration its test chose. */
	readonly build: () => OAuthTokenSettings;
}

const lifetime = (value: unknown, what: string): void => {
	assert.ok(
		isLifetimeSeconds(value),
		`${what} must be a whole number of seconds from 1 to the one-year ceiling (got ${String(value)})`,
	);
};

/** The cases of the `oauthTokenSettings` contract over the settings `input` builds. */
export function oauthTokenSettingsContract(
	input: OAuthTokenSettingsContractInput,
): readonly ContractCase[] {
	const { build } = input;
	return [
		{
			name: "issuer is a canonical issuer",
			run: async () => {
				const { issuer } = build();
				const rejection = checkCanonicalIssuer(issuer);
				assert.equal(
					rejection,
					null,
					rejection === null ? "" : `issuer ${describeIssuerRejection(rejection)}`,
				);
			},
		},
		{
			name: "the access-token lifetime is a default and a max, each a lifetime, the default not above the max",
			run: async () => {
				const { accessTokenLifetime } = build();
				lifetime(accessTokenLifetime?.defaultExpiresIn, "accessTokenLifetime.defaultExpiresIn");
				lifetime(accessTokenLifetime?.maxExpiresIn, "accessTokenLifetime.maxExpiresIn");
				assert.ok(
					accessTokenLifetime.defaultExpiresIn <= accessTokenLifetime.maxExpiresIn,
					"no default the max would cut down: accessTokenLifetime.defaultExpiresIn must not exceed maxExpiresIn",
				);
			},
		},
		{
			name: "the refresh-token lifetime is a lifetime",
			run: async () => {
				lifetime(build().refreshTokenExpiresIn, "refreshTokenExpiresIn");
			},
		},
		{
			name: "carries no token-binding setting: they are core's",
			run: async () => {
				const settings = build() as unknown as Record<string, unknown>;
				for (const member of [
					"tokenBinding",
					"dispatchPolicy",
					"bindConfidentialClientRefreshTokens",
				]) {
					assert.ok(
						!(member in settings),
						`the settings carry ${member}: the token-binding settings are core's, the owner of the token-binding extension point, which reads them from its own configuration with resolveTokenBindingSettings and fills its tokenBindingSettings slot with them — this slot carrying one would be a second source`,
					);
				}
			},
		},
		{
			name: "every switch is true or false",
			run: async () => {
				const settings = build();
				const switches: Record<string, unknown> = {
					resourceIndicatorEnabled: settings.resourceIndicatorEnabled,
					requireEmailVerified: settings.requireEmailVerified,
				};
				for (const [name, value] of Object.entries(switches)) {
					assert.equal(
						typeof value,
						"boolean",
						`${name} must be resolved to true or false, never left absent or as the string an environment variable carries (got ${String(value)})`,
					);
				}
			},
		},
		{
			name: "the settings are frozen, the nested ones too",
			run: async () => {
				const found = unfrozenPath(build(), "the settings");
				assert.equal(
					found,
					undefined,
					`${found} is not frozen: a module that reads the settings could change them under the others`,
				);
			},
		},
	];
}
