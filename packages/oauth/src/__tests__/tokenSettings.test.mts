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
 *   included), and every switch on only when it is `true`. The token-binding
 *   settings are not among them: they are core's, and core reads them.
 * - An issuer that is not canonical is refused, as the oauth router refuses it.
 * - The oauth module provides it eagerly: whenever the module is installed the
 *   slot is filled, whether or not a module requires it, so core's own
 *   machinery can read it too.
 * - It names the slot `authoritative`: while the module is loaded no
 *   composition may substitute it, since the module's own code reads
 *   `oauth {}` and a second source would split what the slot's readers see
 *   from what the module does. A composition without the module fills the
 *   slot itself.
 */

import {
	type AppConfig,
	BootError,
	type ClientRepository,
	type CodeRepository,
	checkOAuthTokenSettings,
	createApp,
	createSymmetricKeyStore,
	defineModule,
	jwksModule,
	memoryAccessTokenDenylistModule,
	type OAuthTokenSettings,
	resolveAccessTokenLifetime,
	resolveRefreshTokenLifetime,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestOAuthTokenSettings,
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
	it("over the fixture configuration: its issuer, the deprecated expiresIn as default and max, every switch off", () => {
		const config = fixture();
		expect(oauthTokenSettingsFrom(config)).toEqual({
			issuer: config.oauth.jwt.issuer,
			legacyTypAccept: false,
			accessTokenLifetime: resolveAccessTokenLifetime(config),
			refreshTokenExpiresIn: resolveRefreshTokenLifetime(config),
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
			resourceIndicatorEnabled: true,
			requireEmailVerified: true,
		});
	});

	it("carries no token-binding setting, whatever the configuration says: they are core's (#728)", () => {
		// The strict policy and the confidential-client binding are configured,
		// and nothing of either is provided.
		const settings = oauthTokenSettingsFrom(everySwitchOn()) as unknown as Record<string, unknown>;
		for (const member of [
			"tokenBinding",
			"dispatchPolicy",
			"bindConfidentialClientRefreshTokens",
		]) {
			expect(Object.keys(settings), member).not.toContain(member);
		}
	});

	it("never outlasts the lifetimes core resolves from the same configuration, so a reader's check answers it", () => {
		// Every reader holds a slot to the configured lifetimes; this provider
		// resolves its lifetimes with the resolvers that check compares with.
		const alias = (): AppConfig => {
			const base = fixture();
			return {
				...base,
				oauth: { ...base.oauth, accessToken: { expiresIn: 7200 } },
			} as AppConfig;
		};
		for (const config of [fixture(), everySwitchOn(), alias()]) {
			const settings = oauthTokenSettingsFrom(config);
			expect(checkOAuthTokenSettings(settings, config)).toEqual(settings);
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
			expect(Object.isFrozen(provided?.accessTokenLifetime)).toBe(true);
		} finally {
			await handle.dispose();
		}
	});
});

describe("the oauth module names oauthTokenSettings authoritative (#728)", () => {
	/** Settings that differ from the configuration's, as a second source would. */
	const SECOND = createTestOAuthTokenSettings({ issuer: "https://second.test" });

	/** A module that requires the slot, and keeps what it was handed. */
	const reader = (seen: { settings?: OAuthTokenSettings }) =>
		defineModule({
			name: "test:token-settings-reader",
			requires: ["oauthTokenSettings"],
			contributes: {
				routes: [
					(deps) => {
						seen.settings = deps.oauthTokenSettings;
						return {
							id: "test-token-settings-reader",
							mountPath: "/__test_token_settings_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});

	it("declares it", () => {
		expect(oauthModule({ config: fixture() }).authoritative).toEqual(["oauthTokenSettings"]);
	});

	it("refuses an override of the slot while the module is loaded, naming the module and the key", async () => {
		// The module goes on reading `oauth {}` — its issuer, its lifetimes —
		// while every reader of the slot would follow the override.
		const config = fixture();
		const caught = await createApp({
			modules: [oauthModule({ config }), ...stubs, reader({})],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
			overrideComponents: { oauthTokenSettings: SECOND },
		}).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(err: unknown) => err,
		);
		expect(caught).toBeInstanceOf(BootError);
		expect((caught as BootError).reason).toBe("authoritative-component-overridden");
		expect((caught as BootError).details).toEqual({
			reason: "authoritative-component-overridden",
			module: "oauth",
			componentKey: "oauthTokenSettings",
		});
	});

	it("lets a composition without the module fill the slot itself", async () => {
		const seen: { settings?: OAuthTokenSettings } = {};
		const config = fixture();
		const handle = await createApp({
			modules: [...stubs, reader(seen)],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
			overrideComponents: { oauthTokenSettings: SECOND },
		});
		try {
			expect(seen.settings).toBe(SECOND);
		} finally {
			await handle.dispose();
		}
	});
});
