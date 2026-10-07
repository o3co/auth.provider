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
 * The oauth module's `oauthTokenSettings`: what modules outside this package
 * read of `oauth {}`, resolved once from the section this module owns and
 * deeply frozen. Each value is what the readers resolve for themselves: the
 * issuer as written, the lifetimes as core's `resolveAccessTokenLifetime` /
 * `resolveRefreshTokenLifetime` read them, and every switch on only when it
 * is `true`.
 *
 * The module fills the slot whenever it is installed, whether or not a module
 * requires it, so core's own machinery can read it too. It names the slot
 * `authoritative` because its own code reads `oauth {}`: a second source would
 * split what the slot's readers see from what the module does.
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
} from "@o3co/auth-provider-core/testing";
import { oauthTokenSettingsContract } from "@o3co/auth-provider-test-kit";
import { describe, expect, it } from "vitest";
import { oauthEndpointsModule } from "#/module.mjs";
import { oauthTokenSettingsFrom } from "#/tokenSettings.mjs";
import { appConfigWithOAuthModule } from "./_helpers/oauthModuleConfig.mjs";
import { withOauthCaptures } from "./_helpers/sections.mjs";

const fixture = () => appConfigWithOAuthModule();

/** The fixture with every switch on, the strict dispatch policy, and the lifetimes on their current keys. */
const everySwitchOn = () => {
	const base = fixture();
	return {
		...base,
		oauth: {
			...base.oauth,
			accessToken: { defaultExpiresIn: 300, maxExpiresIn: 900 },
			refreshToken: { ...base.oauth.refreshToken, expiresIn: 7200 },
			resourceIndicator: { enabled: true },
			requireEmailVerified: true,
		},
		core: {
			...base.core,
			tokenBinding: {
				dispatchPolicy: "strict-mutual-exclusion",
				bindConfidentialClientRefreshTokens: true,
			},
		},
	};
};

describe.each([
	["the fixture configuration", fixture],
	["a configuration with every switch on", everySwitchOn],
] as const)("oauthTokenSettingsFrom keeps core's contract: %s", (_what, config) => {
	it.each(oauthTokenSettingsContract({ build: () => oauthTokenSettingsFrom(config().oauth) }))(
		"$name",
		async ({ run }) => {
			await run();
		},
	);
});

describe("oauthTokenSettingsFrom answers what the readers resolve for themselves today", () => {
	it("over the fixture configuration: its issuer, its default lifetime as default and max, every switch off", () => {
		const config = fixture();
		expect(oauthTokenSettingsFrom(config.oauth)).toEqual({
			issuer: config.oauth.jwt.issuer,
			accessTokenLifetime: resolveAccessTokenLifetime(config),
			refreshTokenExpiresIn: resolveRefreshTokenLifetime(config),
			resourceIndicatorEnabled: false,
			requireEmailVerified: false,
		});
	});

	it("over a configuration with every switch on", () => {
		expect(oauthTokenSettingsFrom(everySwitchOn().oauth)).toEqual({
			issuer: "https://auth.test",
			accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 900 },
			refreshTokenExpiresIn: 7200,
			resourceIndicatorEnabled: true,
			requireEmailVerified: true,
		});
	});

	it("carries no switch for typ-less tokens, even from a hand-built section that carries one", () => {
		const base = fixture();
		const jwt = { ...base.oauth.jwt, legacyTypAccept: true };
		const settings = oauthTokenSettingsFrom({ ...base.oauth, jwt });
		expect(settings).not.toHaveProperty("legacyTypAccept");
	});

	it("carries no token-binding setting, whatever the configuration says: they are core's", () => {
		// The strict policy and the confidential-client binding are configured,
		// and nothing of either is provided.
		const settings = oauthTokenSettingsFrom(everySwitchOn().oauth) as unknown as Record<
			string,
			unknown
		>;
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
		const longerDefault = () => {
			const base = fixture();
			return { ...base, oauth: { ...base.oauth, accessToken: { defaultExpiresIn: 7200 } } };
		};
		for (const config of [fixture(), everySwitchOn(), longerDefault()]) {
			const settings = oauthTokenSettingsFrom(config.oauth);
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
			expect(() => oauthTokenSettingsFrom(config.oauth as never), String(issuer)).toThrow(
				/oauth\.jwt\.issuer/,
			);
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
			modules: [oauthEndpointsModule, ...stubs],
			bootstrapComponents: {
				config: withOauthCaptures(config) as unknown as AppConfig,
				pathResolver: (s: string) => s,
			},
		});
		try {
			const provided = handle.components.oauthTokenSettings;
			expect(provided).toEqual(oauthTokenSettingsFrom(config.oauth));
			expect(Object.isFrozen(provided)).toBe(true);
			expect(Object.isFrozen(provided?.accessTokenLifetime)).toBe(true);
		} finally {
			await handle.dispose();
		}
	});
});

describe("the oauth module names oauthTokenSettings authoritative", () => {
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
		expect(oauthEndpointsModule.authoritative).toEqual(["oauthTokenSettings"]);
	});

	it("refuses an override of the slot while the module is loaded, naming the module and the key", async () => {
		// The module goes on reading `oauth {}` — its issuer, its lifetimes —
		// while every reader of the slot would follow the override.
		const config = fixture();
		const caught = await createApp({
			modules: [oauthEndpointsModule, ...stubs, reader({})],
			bootstrapComponents: {
				config: withOauthCaptures(config) as unknown as AppConfig,
				pathResolver: (s: string) => s,
			},
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
		// Without the module: core's fixture, carrying only the keys of oauth {}
		// core reads.
		const config = makeValidAppConfig();
		const handle = await createApp({
			modules: [...stubs, reader(seen)],
			bootstrapComponents: {
				config: withOauthCaptures(config) as unknown as AppConfig,
				pathResolver: (s: string) => s,
			},
			overrideComponents: { oauthTokenSettings: SECOND },
		});
		try {
			expect(seen.settings).toEqual(SECOND);
		} finally {
			await handle.dispose();
		}
	});
});
