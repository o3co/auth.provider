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
 * The access-token lifetime is two operator values — the DEFAULT every grant
 * mints and the MAX a token-exchange request may ask for — with
 * `oauth.accessToken.expiresIn` a deprecated alias of the default.
 * `resolveAccessTokenLifetime` is the one reader every grant goes through,
 * including for a configuration no section schema parsed. The oauth module's
 * section schema holds the keys to the same rules at boot, and its
 * `reference.conf` ships the defaults: both are pinned by that package's
 * section tests.
 */

import { describe, expect, it } from "vitest";
import { resolveAccessTokenLifetime } from "#/config/application.schema.mjs";

const withAccessToken = (accessToken: Record<string, unknown>) => ({ oauth: { accessToken } });

describe("resolveAccessTokenLifetime", () => {
	it("reads the deprecated expiresIn alone as the default, and the max as that default", () => {
		expect(resolveAccessTokenLifetime(withAccessToken({ expiresIn: 900 }))).toEqual({
			defaultExpiresIn: 900,
			maxExpiresIn: 900,
		});
	});

	it("reads defaultExpiresIn alone, with the max defaulting to it", () => {
		expect(resolveAccessTokenLifetime(withAccessToken({ defaultExpiresIn: 600 }))).toEqual({
			defaultExpiresIn: 600,
			maxExpiresIn: 600,
		});
	});

	it("accepts both keys when they agree", () => {
		expect(
			resolveAccessTokenLifetime(withAccessToken({ expiresIn: 600, defaultExpiresIn: 600 })),
		).toEqual({ defaultExpiresIn: 600, maxExpiresIn: 600 });
	});

	it("lets defaultExpiresIn win when both keys are set and differ", () => {
		// The shipped `reference.conf` keeps its literal on `expiresIn`, so a
		// configuration that adopts the new key always carries both. The new key
		// is the operator's statement; the old one is the shipped default.
		expect(
			resolveAccessTokenLifetime(withAccessToken({ expiresIn: 3600, defaultExpiresIn: 600 })),
		).toEqual({ defaultExpiresIn: 600, maxExpiresIn: 600 });
	});

	it("reads maxExpiresIn when it is set", () => {
		expect(
			resolveAccessTokenLifetime(withAccessToken({ defaultExpiresIn: 600, maxExpiresIn: 3600 })),
		).toEqual({ defaultExpiresIn: 600, maxExpiresIn: 3600 });
	});

	it("accepts a max equal to the default", () => {
		expect(
			resolveAccessTokenLifetime(withAccessToken({ defaultExpiresIn: 600, maxExpiresIn: 600 })),
		).toEqual({ defaultExpiresIn: 600, maxExpiresIn: 600 });
	});

	it("refuses a default above the max, naming both keys", () => {
		expect(() =>
			resolveAccessTokenLifetime(withAccessToken({ defaultExpiresIn: 7200, maxExpiresIn: 3600 })),
		).toThrow(/oauth\.accessToken\.defaultExpiresIn.*oauth\.accessToken\.maxExpiresIn/s);
	});

	it("refuses a default taken from the deprecated alias above the max, and says where it came from", () => {
		expect(() =>
			resolveAccessTokenLifetime(withAccessToken({ expiresIn: 3600, maxExpiresIn: 1800 })),
		).toThrow(/oauth\.accessToken\.expiresIn/);
	});

	it("refuses a configuration that carries no lifetime at all", () => {
		expect(() => resolveAccessTokenLifetime(withAccessToken({}))).toThrow(
			/oauth\.accessToken\.defaultExpiresIn/,
		);
		expect(() => resolveAccessTokenLifetime({ oauth: {} })).toThrow(
			/oauth\.accessToken\.defaultExpiresIn/,
		);
	});

	for (const key of ["defaultExpiresIn", "maxExpiresIn", "expiresIn"] as const) {
		for (const bad of [0, -1, 1.5, Number.NaN, 31_536_001, "3600", null]) {
			it(`refuses ${key} = ${JSON.stringify(bad)} by name rather than minting with it`, () => {
				// A hand-built config never met the schema, so the resolver is the
				// only place these can be caught before `exp` arithmetic uses them.
				const accessToken: Record<string, unknown> = { defaultExpiresIn: 600, [key]: bad };
				if (key === "expiresIn") delete accessToken.defaultExpiresIn;
				expect(() => resolveAccessTokenLifetime(withAccessToken(accessToken))).toThrow(
					new RegExp(`oauth\\.accessToken\\.${key}`),
				);
			});
		}
	}
});
