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
 * mints and the MAX a token-exchange request may ask for.
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
	it("reads defaultExpiresIn alone, with the max defaulting to it", () => {
		expect(resolveAccessTokenLifetime(withAccessToken({ defaultExpiresIn: 600 }))).toEqual({
			defaultExpiresIn: 600,
			maxExpiresIn: 600,
		});
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

	it("refuses a configuration that carries no lifetime at all", () => {
		const required = new RangeError(
			"oauth.accessToken.defaultExpiresIn is required (OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN)",
		);
		expect(() => resolveAccessTokenLifetime(withAccessToken({}))).toThrow(required);
		expect(() => resolveAccessTokenLifetime({ oauth: {} })).toThrow(required);
	});

	it("does not read expiresIn as the default: alone it leaves the default unset", () => {
		expect(() =>
			resolveAccessTokenLifetime(withAccessToken({ expiresIn: 900, maxExpiresIn: 1800 })),
		).toThrow(
			new RangeError(
				"oauth.accessToken.defaultExpiresIn is required (OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN)",
			),
		);
		expect(
			resolveAccessTokenLifetime(withAccessToken({ defaultExpiresIn: 600, expiresIn: 3600 })),
		).toEqual({ defaultExpiresIn: 600, maxExpiresIn: 600 });
	});

	for (const key of ["defaultExpiresIn", "maxExpiresIn"] as const) {
		for (const bad of [0, -1, 1.5, Number.NaN, 31_536_001, "3600", null]) {
			it(`refuses ${key} = ${JSON.stringify(bad)} by name rather than minting with it`, () => {
				// A hand-built config never met the schema, so the resolver is the
				// only place these can be caught before `exp` arithmetic uses them.
				const accessToken: Record<string, unknown> = { defaultExpiresIn: 600, [key]: bad };
				expect(() => resolveAccessTokenLifetime(withAccessToken(accessToken))).toThrow(
					new RegExp(`oauth\\.accessToken\\.${key}`),
				);
			});
		}
	}
});
