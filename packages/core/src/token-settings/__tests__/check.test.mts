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
 * `checkOAuthTokenSettings` (#728): the `oauthTokenSettings` a composition
 * holds, held to what its readers read before any of them reads a member.
 *
 * A reader reads every member from a slot the composition holds, and the
 * configuration only when it holds none — never member by member, which
 * would mix two sources in one reading. So a member a host's slot lacks or
 * gets wrong is refused, naming it, rather than read as `undefined` — which
 * for a switch such as `requireEmailVerified` would quietly turn it off.
 *
 * Its lifetimes are also held to the ones core resolves from the
 * configuration, whoever provides the slot: retention is sized from the
 * configured lifetimes, so a longer slot lifetime would mint a token that
 * outlives the record revoking it.
 */

import { describe, expect, it } from "vitest";
import { MAX_DURATION_SECONDS } from "#/config/durations.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestOAuthTokenSettings } from "#/testing/index.mjs";
import { checkOAuthTokenSettings } from "#/token-settings/check.mjs";

/** The fixture configuration: a 3600 s access-token maximum, a 86 400 s refresh token. */
const CONFIG = makeValidCoreConfig();

/** The fixture configuration with the lifetimes given. */
const configWith = (accessToken: Record<string, number>, refreshExpiresIn: number) => {
	const base = makeValidCoreConfig() as { oauth: Record<string, unknown> };
	return {
		...base,
		oauth: {
			...base.oauth,
			accessToken,
			refreshToken: { ...(base.oauth.refreshToken as object), expiresIn: refreshExpiresIn },
		},
	};
};

/** The double's settings with `change` applied to a copy. */
const settingsWith = (change: (draft: Record<string, unknown>) => void): unknown => {
	const base = createTestOAuthTokenSettings();
	const draft: Record<string, unknown> = {
		...base,
		accessTokenLifetime: { ...base.accessTokenLifetime },
	};
	change(draft);
	return draft;
};

describe("checkOAuthTokenSettings (#728)", () => {
	it("answers settings that keep the contract, as they are", () => {
		const settings = createTestOAuthTokenSettings({
			issuer: "https://auth.example.com/tenant-a",
			legacyTypAccept: true,
			accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: MAX_DURATION_SECONDS },
			refreshTokenExpiresIn: 1,
			resourceIndicatorEnabled: true,
			requireEmailVerified: true,
		});
		const config = configWith({ defaultExpiresIn: 60, maxExpiresIn: MAX_DURATION_SECONDS }, 86_400);
		expect(checkOAuthTokenSettings(settings, config)).toBe(settings);
	});

	it("refuses a lifetime longer than the one core resolves from the configuration, naming the member and both values", () => {
		const longerAccess = createTestOAuthTokenSettings({
			accessTokenLifetime: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
		});
		expect(() => checkOAuthTokenSettings(longerAccess, CONFIG)).toThrow(RangeError);
		expect(() => checkOAuthTokenSettings(longerAccess, CONFIG)).toThrow(
			/oauthTokenSettings\.accessTokenLifetime\.maxExpiresIn.*7200.*3600/,
		);
		const longerRefresh = createTestOAuthTokenSettings({ refreshTokenExpiresIn: 86_401 });
		expect(() => checkOAuthTokenSettings(longerRefresh, CONFIG)).toThrow(RangeError);
		expect(() => checkOAuthTokenSettings(longerRefresh, CONFIG)).toThrow(
			/oauthTokenSettings\.refreshTokenExpiresIn.*86401.*86400/,
		);
	});

	it("answers lifetimes at or under the configuration's", () => {
		for (const settings of [
			createTestOAuthTokenSettings(),
			createTestOAuthTokenSettings({
				accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: 600 },
				refreshTokenExpiresIn: 60,
			}),
		]) {
			expect(checkOAuthTokenSettings(settings, CONFIG)).toBe(settings);
		}
	});

	it("refuses a member that is missing or breaks the contract, naming it", () => {
		const cases: ReadonlyArray<readonly [string, (draft: Record<string, unknown>) => void]> = [
			["oauthTokenSettings.issuer", (d) => delete d.issuer],
			["oauthTokenSettings.issuer", (d) => (d.issuer = "http://auth.example.com")],
			["oauthTokenSettings.issuer", (d) => (d.issuer = "https://auth.test?tenant=a")],
			["oauthTokenSettings.legacyTypAccept", (d) => delete d.legacyTypAccept],
			["oauthTokenSettings.legacyTypAccept", (d) => (d.legacyTypAccept = "true")],
			["oauthTokenSettings.accessTokenLifetime", (d) => delete d.accessTokenLifetime],
			[
				"oauthTokenSettings.accessTokenLifetime",
				(d) => (d.accessTokenLifetime = { defaultExpiresIn: 7200, maxExpiresIn: 3600 }),
			],
			[
				"oauthTokenSettings.accessTokenLifetime",
				(d) => (d.accessTokenLifetime = { defaultExpiresIn: 60 }),
			],
			["oauthTokenSettings.refreshTokenExpiresIn", (d) => delete d.refreshTokenExpiresIn],
			["oauthTokenSettings.refreshTokenExpiresIn", (d) => (d.refreshTokenExpiresIn = 0)],
			[
				"oauthTokenSettings.refreshTokenExpiresIn",
				(d) => (d.refreshTokenExpiresIn = MAX_DURATION_SECONDS + 1),
			],
			["oauthTokenSettings.resourceIndicatorEnabled", (d) => delete d.resourceIndicatorEnabled],
			["oauthTokenSettings.requireEmailVerified", (d) => delete d.requireEmailVerified],
			["oauthTokenSettings.requireEmailVerified", (d) => (d.requireEmailVerified = 1)],
		];
		for (const [member, change] of cases) {
			const value = settingsWith(change);
			const label = `${member} in ${JSON.stringify(value)}`;
			expect(() => checkOAuthTokenSettings(value, CONFIG), label).toThrow(RangeError);
			expect(() => checkOAuthTokenSettings(value, CONFIG), label).toThrow(member);
		}
	});

	it("refuses what is not settings at all", () => {
		for (const value of [null, "https://auth.test", 1, []]) {
			expect(() => checkOAuthTokenSettings(value, CONFIG), JSON.stringify(value)).toThrow(
				/oauthTokenSettings/,
			);
		}
	});

	it("refuses a value it cannot print as JSON with its RangeError, never a TypeError", () => {
		const circular: Record<string, unknown> = {};
		circular.self = circular;
		const cases: ReadonlyArray<readonly [string, unknown]> = [
			["oauthTokenSettings.issuer", settingsWith((d) => (d.issuer = 1n))],
			[
				"oauthTokenSettings.accessTokenLifetime",
				settingsWith((d) => (d.accessTokenLifetime = circular)),
			],
			[
				"oauthTokenSettings.refreshTokenExpiresIn",
				settingsWith((d) => (d.refreshTokenExpiresIn = 1n)),
			],
			[
				"oauthTokenSettings.requireEmailVerified",
				settingsWith((d) => (d.requireEmailVerified = circular)),
			],
			["oauthTokenSettings must be", 1n],
		];
		for (const [named, value] of cases) {
			expect(() => checkOAuthTokenSettings(value, CONFIG), named).toThrow(RangeError);
			expect(() => checkOAuthTokenSettings(value, CONFIG), named).toThrow(named);
		}
	});

	it("leaves alone a member no reader reads", () => {
		const settings = { ...createTestOAuthTokenSettings(), extra: "ignored" };
		expect(checkOAuthTokenSettings(settings, CONFIG)).toBe(settings);
	});
});
