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
 * `oauth.refreshToken.expiresIn` has one reader, `resolveRefreshTokenLifetime`,
 * and it holds the value to the rule the schema holds it to: a whole number of
 * seconds from 1 to a year. The schema only sees a loaded configuration; the
 * resolver is what a configuration built by hand meets, and every grant that
 * mints a refresh token reads through it when it is built.
 */

import { describe, expect, it } from "vitest";
import { AppConfigSchema, resolveRefreshTokenLifetime } from "#/config/application.schema.mjs";
import * as core from "#/index.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

const withRefreshToken = (refreshToken: Record<string, unknown>) => ({ oauth: { refreshToken } });

describe("resolveRefreshTokenLifetime", () => {
	it("is exported from the package root", () => {
		expect(typeof core.resolveRefreshTokenLifetime).toBe("function");
		expect(core.resolveRefreshTokenLifetime).toBe(resolveRefreshTokenLifetime);
	});

	it("reads the configured lifetime in seconds, the one-year ceiling included", () => {
		expect(resolveRefreshTokenLifetime(withRefreshToken({ expiresIn: 86_400 }))).toBe(86_400);
		expect(resolveRefreshTokenLifetime(withRefreshToken({ expiresIn: 1 }))).toBe(1);
		expect(resolveRefreshTokenLifetime(withRefreshToken({ expiresIn: 31_536_000 }))).toBe(
			31_536_000,
		);
	});

	for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 31_536_001, "86400", null]) {
		it(`refuses expiresIn = ${String(bad)} with a RangeError that names the key`, () => {
			expect(() => resolveRefreshTokenLifetime(withRefreshToken({ expiresIn: bad }))).toThrow(
				RangeError,
			);
			expect(() => resolveRefreshTokenLifetime(withRefreshToken({ expiresIn: bad }))).toThrow(
				/oauth\.refreshToken\.expiresIn/,
			);
		});
	}

	it("refuses a configuration that carries no refresh-token lifetime at all", () => {
		for (const config of [withRefreshToken({}), { oauth: {} }]) {
			expect(() => resolveRefreshTokenLifetime(config), JSON.stringify(config)).toThrow(
				/oauth\.refreshToken\.expiresIn/,
			);
		}
	});

	it("refuses every number the schema refuses, so a hand-built configuration meets the same rule", () => {
		for (const expiresIn of [0, -1, 1.5, Number.NaN, 31_536_001]) {
			const base = makeValidAppConfig();
			const parsed = AppConfigSchema.safeParse({
				...base,
				oauth: { ...base.oauth, refreshToken: { ...base.oauth.refreshToken, expiresIn } },
			});
			expect(parsed.success, String(expiresIn)).toBe(false);
			expect(() => resolveRefreshTokenLifetime(withRefreshToken({ expiresIn }))).toThrow(
				RangeError,
			);
		}
	});
});

describe("isLifetimeSeconds — the rule both lifetime resolvers apply", () => {
	it("is exported, for a lifetime handed over as a number rather than as configuration", () => {
		expect(typeof core.isLifetimeSeconds).toBe("function");
	});

	it("admits a whole number of seconds from 1 to a year, and nothing else", () => {
		for (const good of [1, 60, 86_400, 31_536_000]) {
			expect(core.isLifetimeSeconds(good), String(good)).toBe(true);
			expect(resolveRefreshTokenLifetime(withRefreshToken({ expiresIn: good }))).toBe(good);
		}
		for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 31_536_001, "60", null]) {
			expect(core.isLifetimeSeconds(bad), String(bad)).toBe(false);
			expect(() => resolveRefreshTokenLifetime(withRefreshToken({ expiresIn: bad }))).toThrow();
		}
	});
});
