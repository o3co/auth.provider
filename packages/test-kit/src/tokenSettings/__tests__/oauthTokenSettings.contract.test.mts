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
 * `oauthTokenSettingsContract` run over core's double of the
 * `oauthTokenSettings` slot, and the proof that each case is not vacuous:
 * settings broken one way each, refused by the case that names what they
 * break.
 */

import type { OAuthTokenSettings } from "@o3co/auth-provider-core";
import { createTestOAuthTokenSettings } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { type OAuthTokenSettingsContractInput, oauthTokenSettingsContract } from "#/index.mjs";

const RULES = {
	issuer: "issuer is a canonical issuer",
	accessToken:
		"the access-token lifetime is a default and a max, each a lifetime, the default not above the max",
	refreshToken: "the refresh-token lifetime is a lifetime",
	tokenBinding: "carries no token-binding setting: they are core's",
	switches: "every switch is true or false",
	frozen: "the settings are frozen, the nested ones too",
} as const;

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

describe("oauthTokenSettingsContract — core's double", () => {
	const cases = oauthTokenSettingsContract({ build: () => createTestOAuthTokenSettings() });

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.issuer,
			RULES.accessToken,
			RULES.refreshToken,
			RULES.tokenBinding,
			RULES.switches,
			RULES.frozen,
		]);
	});

	for (const contractCase of cases) {
		it(contractCase.name, contractCase.run);
	}

	it("keeps them with every override a deployment could configure", async () => {
		expect(
			await failing(() =>
				createTestOAuthTokenSettings({
					issuer: "https://idp.example.com/tenant-a",
					accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 86_400 },
					refreshTokenExpiresIn: 2_592_000,
					resourceIndicatorEnabled: true,
					requireEmailVerified: true,
				}),
			),
		).toEqual([]);
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
			expect(await failing(() => createTestOAuthTokenSettings({ issuer }))).toEqual([RULES.issuer]);
		}
	});

	it("an access-token lifetime that is not one, or a default above the max", async () => {
		for (const accessTokenLifetime of [
			{ defaultExpiresIn: 0 },
			{ defaultExpiresIn: 1.5 },
			{ maxExpiresIn: 31_536_001, defaultExpiresIn: 60 },
			{ defaultExpiresIn: 7200, maxExpiresIn: 3600 },
		]) {
			expect(await failing(() => createTestOAuthTokenSettings({ accessTokenLifetime }))).toEqual([
				RULES.accessToken,
			]);
		}
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.accessTokenLifetime = Object.freeze({ defaultExpiresIn: 3600 });
				}),
			),
		).toEqual([RULES.accessToken]);
	});

	it("a refresh-token lifetime that is not one", async () => {
		for (const refreshTokenExpiresIn of [0, -1, 60.5, 31_536_001, Number.NaN]) {
			expect(await failing(() => createTestOAuthTokenSettings({ refreshTokenExpiresIn }))).toEqual([
				RULES.refreshToken,
			]);
		}
	});

	it("a token-binding setting, nested or not: they are core's, and a slot that carried one would be a second source", async () => {
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.tokenBinding = Object.freeze({ dispatchPolicy: "strict-mutual-exclusion" });
				}),
			),
		).toEqual([RULES.tokenBinding]);
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.dispatchPolicy = "strict-mutual-exclusion";
				}),
			),
		).toEqual([RULES.tokenBinding]);
		for (const value of [true, false]) {
			expect(
				await failing(() =>
					settingsWith((draft) => {
						draft.bindConfidentialClientRefreshTokens = value;
					}),
				),
			).toEqual([RULES.tokenBinding]);
		}
	});

	it("a switch that is not a boolean: absent, or a string an environment variable left unread", async () => {
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.requireEmailVerified = "true";
				}),
			),
		).toEqual([RULES.switches]);
		expect(
			await failing(() =>
				settingsWith((draft) => {
					delete draft.requireEmailVerified;
				}),
			),
		).toEqual([RULES.switches]);
		expect(
			await failing(() =>
				settingsWith((draft) => {
					draft.resourceIndicatorEnabled = 1;
				}),
			),
		).toEqual([RULES.switches]);
	});

	it("settings a reader could change under the others", async () => {
		const base = createTestOAuthTokenSettings();
		expect(await failing(() => ({ ...base }))).toEqual([RULES.frozen]);
		expect(
			await failing(() =>
				Object.freeze({ ...base, accessTokenLifetime: { ...base.accessTokenLifetime } }),
			),
		).toEqual([RULES.frozen]);
	});
});
