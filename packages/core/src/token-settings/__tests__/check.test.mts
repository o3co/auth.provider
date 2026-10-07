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
 * `checkOAuthTokenSettings`: the `oauthTokenSettings` a composition holds,
 * held to what its readers read before any of them reads a member.
 *
 * A reader reads every member from the composition's slot, or from the
 * configuration when the composition holds none — never member by member,
 * which would mix two sources in one reading. So a member a host's slot lacks or gets wrong
 * is refused by name rather than read as `undefined`, which for a switch
 * such as `requireEmailVerified` would quietly turn it off. Lifetimes are
 * held to those core resolves from the configuration, whoever provides the
 * slot: retention is sized from the configured lifetimes, so a longer slot
 * lifetime would mint a token that outlives the record revoking it.
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

/** A member missing or breaking its contract rule, and the name its refusal carries. */
const MEMBER_CASES: ReadonlyArray<readonly [string, (draft: Record<string, unknown>) => void]> = [
	["oauthTokenSettings.issuer", (d) => delete d.issuer],
	["oauthTokenSettings.issuer", (d) => (d.issuer = "http://auth.example.com")],
	["oauthTokenSettings.issuer", (d) => (d.issuer = "https://auth.test?tenant=a")],
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

describe("checkOAuthTokenSettings", () => {
	it("answers settings that keep the contract, as they are", () => {
		const settings = createTestOAuthTokenSettings({
			issuer: "https://auth.example.com/tenant-a",
			accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: MAX_DURATION_SECONDS },
			refreshTokenExpiresIn: 1,
			resourceIndicatorEnabled: true,
			requireEmailVerified: true,
		});
		const config = configWith({ defaultExpiresIn: 60, maxExpiresIn: MAX_DURATION_SECONDS }, 86_400);
		expect(checkOAuthTokenSettings(settings, config)).toEqual(settings);
	});

	it("answers no switch for typ-less tokens, even from a hand-filled slot that carries one", () => {
		const slot = { ...createTestOAuthTokenSettings(), legacyTypAccept: true };
		expect(checkOAuthTokenSettings(slot, CONFIG)).not.toHaveProperty("legacyTypAccept");
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

	it("names, for each member, the reader that sizes a record from the configured lifetime and cannot read the slot", () => {
		const refusal = (settings: unknown): string => {
			try {
				checkOAuthTokenSettings(settings, CONFIG);
			} catch (err) {
				return (err as Error).message;
			}
			throw new Error("expected a refusal");
		};
		// The access-token maximum sizes how long the refresh-token family
		// modules remember a revoked family; the family's own expiry follows the
		// slot's refresh-token lifetime, so the refresh member is not theirs.
		const access = refusal(
			createTestOAuthTokenSettings({
				accessTokenLifetime: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
			}),
		);
		expect(access).toMatch(/refresh-token family modules/);
		expect(access).toMatch(/revoked family/);
		expect(access).not.toMatch(/session lifecycle/);
		// The refresh-token lifetime sizes how long the session lifecycle keeps a
		// closing session's record.
		const refresh = refusal(createTestOAuthTokenSettings({ refreshTokenExpiresIn: 86_401 }));
		expect(refresh).toMatch(/session lifecycle/);
		expect(refresh).toMatch(/closing session's record/);
		expect(refresh).not.toMatch(/refresh-token family modules/);
		for (const message of [access, refresh]) {
			expect(message).toMatch(/not the slot/);
			// The subject revocation boundary is sized from the slot where one is
			// held, so no refusal claims the configuration bounds it.
			expect(message).not.toMatch(/subject revocation/);
		}
	});

	it("answers lifetimes at or under the configuration's", () => {
		for (const settings of [
			createTestOAuthTokenSettings(),
			createTestOAuthTokenSettings({
				accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: 600 },
				refreshTokenExpiresIn: 60,
			}),
		]) {
			expect(checkOAuthTokenSettings(settings, CONFIG)).toEqual(settings);
		}
	});

	it("refuses a member that is missing or breaks the contract, naming it", () => {
		for (const [member, change] of MEMBER_CASES) {
			const value = settingsWith(change);
			const label = `${member} in ${JSON.stringify(value)}`;
			expect(() => checkOAuthTokenSettings(value, CONFIG), label).toThrow(RangeError);
			expect(() => checkOAuthTokenSettings(value, CONFIG), label).toThrow(member);
			// The refusal states the rule it enforces, with no issue number.
			expect(() => checkOAuthTokenSettings(value, CONFIG), label).not.toThrow(/#\d/);
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

	it("reads only the members readers read: one no reader reads is neither refused nor carried", () => {
		const settings = createTestOAuthTokenSettings();
		expect(checkOAuthTokenSettings({ ...settings, extra: "ignored" }, CONFIG)).toEqual(settings);
	});

	describe("answers a snapshot: each member read once, validated, and frozen", () => {
		/** The double's settings, as a mutable object a host could hold on to. */
		const mutable = () => {
			const base = createTestOAuthTokenSettings();
			return { ...base, accessTokenLifetime: { ...base.accessTokenLifetime } };
		};

		it("answers what a getter answered when it was read, not what it answers afterwards", () => {
			let reads = 0;
			const value = {
				...mutable(),
				accessTokenLifetime: {
					defaultExpiresIn: 60,
					get maxExpiresIn() {
						reads += 1;
						return reads === 1 ? 3600 : 7200;
					},
				},
			};
			const checked = checkOAuthTokenSettings(value, CONFIG);
			expect(checked.accessTokenLifetime.maxExpiresIn).toBe(3600);
			expect(checked.accessTokenLifetime.maxExpiresIn).toBe(3600);
			expect(reads).toBe(1);
		});

		it("keeps what it answered when the host changes its object afterwards", () => {
			const host = mutable();
			const checked = checkOAuthTokenSettings(host, CONFIG);
			host.requireEmailVerified = true;
			host.resourceIndicatorEnabled = true;
			host.accessTokenLifetime.maxExpiresIn = 7200;
			host.refreshTokenExpiresIn = 172_800;
			expect(checked.requireEmailVerified).toBe(false);
			expect(checked.resourceIndicatorEnabled).toBe(false);
			expect(checked.accessTokenLifetime.maxExpiresIn).toBe(3600);
			expect(checked.refreshTokenExpiresIn).toBe(86_400);
		});

		it("answers a value frozen at every level", () => {
			const checked = checkOAuthTokenSettings(mutable(), CONFIG);
			expect(Object.isFrozen(checked)).toBe(true);
			expect(Object.isFrozen(checked.accessTokenLifetime)).toBe(true);
		});

		it("refuses a member whose read throws, naming it", () => {
			const cases: ReadonlyArray<readonly [string, () => unknown]> = [
				[
					"oauthTokenSettings.issuer",
					() => ({
						...mutable(),
						get issuer(): string {
							throw new Error("read me not");
						},
					}),
				],
				[
					"oauthTokenSettings.accessTokenLifetime",
					() => ({
						...mutable(),
						accessTokenLifetime: {
							defaultExpiresIn: 60,
							get maxExpiresIn(): number {
								throw new Error("read me not");
							},
						},
					}),
				],
				[
					"oauthTokenSettings.requireEmailVerified",
					() => ({
						...mutable(),
						get requireEmailVerified(): boolean {
							throw new Error("read me not");
						},
					}),
				],
			];
			for (const [member, build] of cases) {
				expect(() => checkOAuthTokenSettings(build(), CONFIG), member).toThrow(RangeError);
				expect(() => checkOAuthTokenSettings(build(), CONFIG), member).toThrow(member);
			}
		});
	});
});

describe("checkOAuthTokenSettings without the configuration", () => {
	it("answers settings that keep the contract, whatever the configuration's lifetimes", () => {
		// Lifetimes the fixture configuration would refuse: without it, the
		// check holds the slot to its contract alone. Boot holds a held slot to
		// the configured lifetimes itself.
		const settings = createTestOAuthTokenSettings({
			accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: MAX_DURATION_SECONDS },
			refreshTokenExpiresIn: MAX_DURATION_SECONDS,
		});
		expect(checkOAuthTokenSettings(settings)).toEqual(settings);
	});

	it("refuses a member that is missing or breaks the contract, naming it", () => {
		for (const [member, change] of MEMBER_CASES) {
			const value = settingsWith(change);
			const label = `${member} in ${JSON.stringify(value)}`;
			expect(() => checkOAuthTokenSettings(value), label).toThrow(RangeError);
			expect(() => checkOAuthTokenSettings(value), label).toThrow(member);
		}
	});

	it("refuses what is not settings at all", () => {
		for (const value of [undefined, null, "https://auth.test", 1, []]) {
			expect(() => checkOAuthTokenSettings(value), String(value)).toThrow(RangeError);
			expect(() => checkOAuthTokenSettings(value), String(value)).toThrow(/oauthTokenSettings/);
		}
	});

	it("answers a snapshot frozen at every level", () => {
		const base = createTestOAuthTokenSettings();
		const host = { ...base, accessTokenLifetime: { ...base.accessTokenLifetime } };
		const checked = checkOAuthTokenSettings(host);
		host.accessTokenLifetime.maxExpiresIn = 7200;
		expect(checked.accessTokenLifetime.maxExpiresIn).toBe(base.accessTokenLifetime.maxExpiresIn);
		expect(Object.isFrozen(checked)).toBe(true);
		expect(Object.isFrozen(checked.accessTokenLifetime)).toBe(true);
	});

	it("still holds the lifetimes to a configuration a caller passes, even one that resolves none", () => {
		const longer = createTestOAuthTokenSettings({ refreshTokenExpiresIn: 86_401 });
		expect(() => checkOAuthTokenSettings(longer, CONFIG)).toThrow(
			/oauthTokenSettings\.refreshTokenExpiresIn.*86401.*86400/,
		);
		// Passing a configuration is the transitional form even when the value
		// is `undefined`: the configuration's absence is refused, never read as
		// the configuration-free form.
		expect(() => checkOAuthTokenSettings(createTestOAuthTokenSettings(), undefined)).toThrow();
	});
});
