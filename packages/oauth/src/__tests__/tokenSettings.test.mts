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
 * The oauth module's `oauthTokenSettings` (#728): what modules outside this
 * package read of `oauth {}`, resolved once from the section this module owns
 * and deeply frozen.
 *
 * - `oauthTokenSettingsFrom` keeps core's contract (`oauthTokenSettingsContract`)
 *   over the fixture configuration and one with every switch on.
 * - Each value is what the readers resolve for themselves today: the
 *   issuer as written, the lifetimes as core's `resolveAccessTokenLifetime` /
 *   `resolveRefreshTokenLifetime` read them (the deprecated `expiresIn`
 *   included), the dispatch policy as core's token-binding middleware reads
 *   it, and every switch on only when it is `true`.
 * - An issuer that is not canonical is refused, as the oauth router refuses it.
 * - The oauth module provides it eagerly: whenever the module is installed the
 *   slot is filled, whether or not a module requires it, so core's own
 *   machinery can read it too.
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	defineModule,
	jwksModule,
	memoryAccessTokenDenylistModule,
	resolveAccessTokenLifetime,
	resolveRefreshTokenLifetime,
	resolveTokenBindingDispatchPolicy,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	makeValidAppConfig,
	oauthTokenSettingsContract,
} from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { oauthModule } from "#/module.mjs";
import { oauthTokenSettingsFrom } from "#/tokenSettings.mjs";

const fixture = (): AppConfig => makeValidAppConfig() as AppConfig;

/** The fixture with every switch on, the strict dispatch policy, and the lifetimes on their current keys. */
const everySwitchOn = (): AppConfig => {
	const base = fixture();
	return {
		...base,
		oauth: {
			...base.oauth,
			jwt: { ...base.oauth.jwt, legacyTypAccept: true },
			accessToken: { defaultExpiresIn: 300, maxExpiresIn: 900 },
			refreshToken: { ...base.oauth.refreshToken, expiresIn: 7200 },
			tokenBinding: {
				"dispatch-policy": "strict-mutual-exclusion",
				bindConfidentialClientRefreshTokens: true,
			},
			resourceIndicator: { enabled: true },
			requireEmailVerified: true,
		},
	} as AppConfig;
};

describe.each([
	["the fixture configuration", fixture],
	["a configuration with every switch on", everySwitchOn],
] as const)("oauthTokenSettingsFrom keeps core's contract: %s", (_what, config) => {
	it.each(oauthTokenSettingsContract({ build: () => oauthTokenSettingsFrom(config()) }))(
		"$name",
		async ({ run }) => {
			await run();
		},
	);
});

describe("oauthTokenSettingsFrom answers what the readers resolve for themselves today", () => {
	it("over the fixture configuration: its issuer, the deprecated expiresIn as default and max, the intent-explicit policy, every switch off", () => {
		const config = fixture();
		expect(oauthTokenSettingsFrom(config)).toEqual({
			issuer: config.oauth.jwt.issuer,
			legacyTypAccept: false,
			accessTokenLifetime: resolveAccessTokenLifetime(config),
			refreshTokenExpiresIn: resolveRefreshTokenLifetime(config),
			tokenBinding: {
				dispatchPolicy: "intent-explicit",
				bindConfidentialClientRefreshTokens: false,
			},
			resourceIndicatorEnabled: false,
			requireEmailVerified: false,
		});
	});

	it("over a configuration with every switch on", () => {
		expect(oauthTokenSettingsFrom(everySwitchOn())).toEqual({
			issuer: "https://auth.test",
			legacyTypAccept: true,
			accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 900 },
			refreshTokenExpiresIn: 7200,
			tokenBinding: {
				dispatchPolicy: "strict-mutual-exclusion",
				bindConfidentialClientRefreshTokens: true,
			},
			resourceIndicatorEnabled: true,
			requireEmailVerified: true,
		});
	});

	it("reads the dispatch policy through core's resolveTokenBindingDispatchPolicy, which boot reads without this module", () => {
		const base = fixture();
		for (const policy of ["strict-mutual-exclusion", "intent-explicit", "mutual", undefined]) {
			const config = {
				...base,
				oauth: {
					...base.oauth,
					tokenBinding: { ...base.oauth.tokenBinding, "dispatch-policy": policy },
				},
			} as unknown as AppConfig;
			expect(oauthTokenSettingsFrom(config).tokenBinding.dispatchPolicy, String(policy)).toBe(
				resolveTokenBindingDispatchPolicy(config),
			);
		}
	});

	it("refuses an issuer that is not canonical, naming the key", () => {
		const base = fixture();
		for (const issuer of ["auth.test", "http://auth.test", "https://auth.test?x=1", undefined]) {
			const config = {
				...base,
				oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer } },
			} as unknown as AppConfig;
			expect(() => oauthTokenSettingsFrom(config), String(issuer)).toThrow(/oauth\.jwt\.issuer/);
		}
	});
});

// ---------------------------------------------------------------------------
// The oauth module provides it
// ---------------------------------------------------------------------------

const stubs = [
	defineModule({
		name: "test:client-repository",
		provides: {
			clientRepository: (): ClientRepository => ({
				findById: async () => null,
				authenticate: async () => null,
			}),
		},
	}),
	defineModule({
		name: "test:code-repository",
		provides: {
			codeRepository: (): CodeRepository => ({
				createCode: async () =>
					({ code: "c", client_id: "a", redirect_uri: "https://rp.test/cb" }) as never,
				findByCode: async () => null,
				consumeByCode: async () => null,
				removeByCode: async () => {},
			}),
		},
	}),
	defineModule({
		name: "test:key-store",
		provides: { keyStore: () => createSymmetricKeyStore("test-secret-for-oauth-module!!!!!") },
	}),
	memoryAccessTokenDenylistModule,
	jwksModule,
];

describe("the oauth module provides oauthTokenSettings", () => {
	it("fills the slot whenever it is installed, with no module requiring it, resolved from the configuration", async () => {
		const config = everySwitchOn();
		const handle = await createTestApp({
			modules: [oauthModule({ config }), ...stubs],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		try {
			const provided = handle.components.oauthTokenSettings;
			expect(provided).toEqual(oauthTokenSettingsFrom(config));
			expect(Object.isFrozen(provided)).toBe(true);
			expect(Object.isFrozen(provided?.tokenBinding)).toBe(true);
			expect(Object.isFrozen(provided?.accessTokenLifetime)).toBe(true);
		} finally {
			await handle.dispose();
		}
	});
});
