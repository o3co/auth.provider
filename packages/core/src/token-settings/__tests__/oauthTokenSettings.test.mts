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
 * The `oauthTokenSettings` slot (#728): what other modules read of the oauth
 * module's token settings, its contract suite and the test double. The
 * double keeps every case; each way a value can break the contract fails
 * the case that names it. The token-binding dispatch policy is not among
 * the settings: it is core's, the owner of the token-binding extension
 * point, and core reads it itself.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { AccessTokenLifetime } from "#/config/application.schema.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	createTestOAuthTokenSettings,
	type OAuthTokenSettingsContractInput,
	oauthTokenSettingsContract,
} from "#/testing/index.mjs";
import type { OAuthTokenSettings } from "#/token-settings/types.mjs";

/** The names of the cases `build` fails. */
const failing = async (build: OAuthTokenSettingsContractInput["build"]): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of oauthTokenSettingsContract({ build })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** The double's settings with `change` applied to a mutable copy, frozen again as a provider would hand them. */
const settingsWith = (change: (draft: Record<string, unknown>) => void): OAuthTokenSettings => {
	const base = createTestOAuthTokenSettings();
	const draft: Record<string, unknown> = {
		...base,
		accessTokenLifetime: { ...base.accessTokenLifetime },
	};
	change(draft);
	Object.freeze(draft.accessTokenLifetime);
	return Object.freeze(draft) as unknown as OAuthTokenSettings;
};

describe("the oauthTokenSettings slot", () => {
	it("is optional, and holds the settings other modules read of the oauth module's", () => {
		expectTypeOf<ComponentMap["oauthTokenSettings"]>().toEqualTypeOf<
			OAuthTokenSettings | undefined
		>();
		expectTypeOf<
			ProviderDeps<"oauthTokenSettings">["oauthTokenSettings"]
		>().toEqualTypeOf<OAuthTokenSettings>();
		expectTypeOf<OAuthTokenSettings["issuer"]>().toEqualTypeOf<string>();
		expectTypeOf<OAuthTokenSettings["legacyTypAccept"]>().toEqualTypeOf<boolean>();
		expectTypeOf<OAuthTokenSettings["accessTokenLifetime"]>().toEqualTypeOf<AccessTokenLifetime>();
		expectTypeOf<OAuthTokenSettings["refreshTokenExpiresIn"]>().toEqualTypeOf<number>();
		expectTypeOf<
			OAuthTokenSettings["bindConfidentialClientRefreshTokens"]
		>().toEqualTypeOf<boolean>();
		// The dispatch policy is core's (#728): the slot has no member for it.
		expectTypeOf<OAuthTokenSettings>().not.toHaveProperty("tokenBinding");
		expectTypeOf<OAuthTokenSettings>().not.toHaveProperty("dispatchPolicy");
		expectTypeOf<OAuthTokenSettings["resourceIndicatorEnabled"]>().toEqualTypeOf<boolean>();
		expectTypeOf<OAuthTokenSettings["requireEmailVerified"]>().toEqualTypeOf<boolean>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const settings = createTestOAuthTokenSettings();
		let seen: OAuthTokenSettings | undefined;
		const owner = defineModule({
			name: "test:token-settings-owner",
			provides: { oauthTokenSettings: () => settings },
		});
		const reader = defineModule({
			name: "test:token-settings-reader",
			requires: ["oauthTokenSettings"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.oauthTokenSettings;
						return {
							id: "test-token-settings-reader",
							mountPath: "/__test_token_settings_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [owner, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen).toBe(settings);
		} finally {
			await handle.dispose();
		}
	});
});

describe("oauthTokenSettingsContract — the double", () => {
	const cases = oauthTokenSettingsContract({ build: () => createTestOAuthTokenSettings() });

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			"issuer is a canonical issuer",
			"the access-token lifetime is a default and a max, each a lifetime, the default not above the max",
			"the refresh-token lifetime is a lifetime",
			"carries no token-binding dispatch policy: the policy is core's",
			"every switch is true or false",
			"the settings are frozen, the nested ones too",
		]);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});

	it("keeps them with every override a deployment could configure", async () => {
		expect(
			await failing(() =>
				createTestOAuthTokenSettings({
					issuer: "https://idp.example.com/tenant-a",
					legacyTypAccept: true,
					accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 86_400 },
					refreshTokenExpiresIn: 2_592_000,
					bindConfidentialClientRefreshTokens: true,
					resourceIndicatorEnabled: true,
					requireEmailVerified: true,
				}),
			),
		).toEqual([]);
	});
});

describe("createTestOAuthTokenSettings", () => {
	it("answers the fixture configuration's settings, resolved: nothing absent, every switch off", () => {
		expect(createTestOAuthTokenSettings()).toStrictEqual({
			issuer: "https://auth.test",
			legacyTypAccept: false,
			accessTokenLifetime: { defaultExpiresIn: 3600, maxExpiresIn: 3600 },
			refreshTokenExpiresIn: 86_400,
			bindConfidentialClientRefreshTokens: false,
			resourceIndicatorEnabled: false,
			requireEmailVerified: false,
		});
	});

	it("applies an override, a nested one member by member", () => {
		const settings = createTestOAuthTokenSettings({
			accessTokenLifetime: { maxExpiresIn: 7200 },
			bindConfidentialClientRefreshTokens: true,
		});
		expect(settings.accessTokenLifetime).toStrictEqual({
			defaultExpiresIn: 3600,
			maxExpiresIn: 7200,
		});
		expect(settings.bindConfidentialClientRefreshTokens).toBe(true);
	});

	it("does not check what it is handed: a test of a broken value builds it here", () => {
		expect(createTestOAuthTokenSettings({ issuer: "not a url" }).issuer).toBe("not a url");
	});
});

describe("oauthTokenSettingsContract — each way a value can break it", () => {
	it("an issuer that is not canonical: a bare path, a query, a fragment, credentials, not https", async () => {
		for (const issuer of [
			"/auth",
			"https://auth.test?tenant=a",
			"https://auth.test#top",
			"https://user:secret@auth.test",
			"http://auth.example.com",
			"",
		]) {
			expect(await failing(() => createTestOAuthTokenSettings({ issuer }))).toEqual([
				"issuer is a canonical issuer",
			]);
		}
	});

	it("an access-token lifetime that is not one, or a default above the max", async () => {
		const rule =
			"the access-token lifetime is a default and a max, each a lifetime, the default not above the max";
		for (const accessTokenLifetime of [
			{ defaultExpiresIn: 0 },
			{ defaultExpiresIn: 1.5 },
			{ maxExpiresIn: 31_536_001, defaultExpiresIn: 60 },
			{ defaultExpiresIn: 7200, maxExpiresIn: 3600 },
		]) {
			expect(await failing(() => createTestOAuthTokenSettings({ accessTokenLifetime }))).toEqual([
				rule,
			]);
		}
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.accessTokenLifetime = Object.freeze({ defaultExpiresIn: 3600 });
				}),
			),
		).toEqual([rule]);
	});

	it("a refresh-token lifetime that is not one", async () => {
		for (const refreshTokenExpiresIn of [0, -1, 60.5, 31_536_001, Number.NaN]) {
			expect(await failing(() => createTestOAuthTokenSettings({ refreshTokenExpiresIn }))).toEqual([
				"the refresh-token lifetime is a lifetime",
			]);
		}
	});

	it("a dispatch policy, nested or not: the policy is core's, and a slot that carried one would be a second source", async () => {
		const rule = "carries no token-binding dispatch policy: the policy is core's";
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.tokenBinding = Object.freeze({ dispatchPolicy: "strict-mutual-exclusion" });
				}),
			),
		).toEqual([rule]);
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.dispatchPolicy = "strict-mutual-exclusion";
				}),
			),
		).toEqual([rule]);
	});

	it("a switch that is not a boolean: absent, or a string an environment variable left unread", async () => {
		const rule = "every switch is true or false";
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.requireEmailVerified = "true";
				}),
			),
		).toEqual([rule]);
		expect(
			await failing(() =>
				settingsWith((draft) => {
					delete draft.legacyTypAccept;
				}),
			),
		).toEqual([rule]);
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.resourceIndicatorEnabled = 1;
				}),
			),
		).toEqual([rule]);
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.bindConfidentialClientRefreshTokens = undefined;
				}),
			),
		).toEqual([rule]);
	});

	it("settings a reader could change under the others", async () => {
		const rule = "the settings are frozen, the nested ones too";
		const base = createTestOAuthTokenSettings();
		expect(await failing(() => ({ ...base }))).toEqual([rule]);
		expect(
			await failing(() =>
				Object.freeze({ ...base, accessTokenLifetime: { ...base.accessTokenLifetime } }),
			),
		).toEqual([rule]);
	});
});
