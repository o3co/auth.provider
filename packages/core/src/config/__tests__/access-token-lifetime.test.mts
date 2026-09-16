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
 * mints and the MAX a token-exchange request may ask for — with the original
 * `oauth.accessToken.expiresIn` kept as a deprecated alias of the default.
 *
 * Three layers have to agree on what that means, and each is pinned here:
 *
 *  - `resolveAccessTokenLifetime`, the one reader every grant goes through,
 *    including for hand-built configs that never met the schema;
 *  - the schema, which fails boot on a default above the max and mirrors the
 *    resolved default onto `expiresIn` for readers written before the split;
 *  - `reference.conf`, whose shipped literal sits on the deprecated key so an
 *    override of that key in a higher layer keeps deciding the default.
 */

import { fileURLToPath } from "node:url";
import { parseFile, parseString } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import {
	AppConfigSchema,
	CoreConfigSchema,
	resolveAccessTokenLifetime,
} from "#/config/application.schema.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

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

describe("oauth.accessToken schema", () => {
	const accessTokenSchema = CoreConfigSchema.shape.oauth.shape.accessToken;

	function issues(input: unknown): { path: string; message: string }[] {
		const result = AppConfigSchema.safeParse({
			...makeValidAppConfig(),
			oauth: { ...makeValidAppConfig().oauth, accessToken: input },
		});
		return result.success
			? []
			: result.error.issues.map((i) => ({ path: i.path.join("."), message: i.message }));
	}

	it("keeps the deprecated alias working on its own, leaving the new keys absent", () => {
		expect(accessTokenSchema.parse({ expiresIn: 900 })).toEqual({ expiresIn: 900 });
	});

	it("mirrors defaultExpiresIn onto expiresIn, so readers of the old key see the resolved default", () => {
		expect(accessTokenSchema.parse({ defaultExpiresIn: 600 })).toEqual({
			defaultExpiresIn: 600,
			expiresIn: 600,
		});
	});

	it("overwrites a differing expiresIn with defaultExpiresIn", () => {
		expect(accessTokenSchema.parse({ expiresIn: 3600, defaultExpiresIn: 600 })).toEqual({
			defaultExpiresIn: 600,
			expiresIn: 600,
		});
	});

	it("keeps maxExpiresIn as given", () => {
		expect(accessTokenSchema.parse({ defaultExpiresIn: 600, maxExpiresIn: 3600 })).toEqual({
			defaultExpiresIn: 600,
			maxExpiresIn: 3600,
			expiresIn: 600,
		});
	});

	it("is idempotent, so createApp's second parse of a loaded config changes nothing", () => {
		const once = accessTokenSchema.parse({
			expiresIn: 3600,
			defaultExpiresIn: 600,
			maxExpiresIn: 900,
		});
		expect(accessTokenSchema.parse(once)).toEqual(once);
	});

	it("fails boot on a default above the max, naming both keys", () => {
		const found = issues({ defaultExpiresIn: 7200, maxExpiresIn: 3600 });
		expect(found).toHaveLength(1);
		expect(found[0]?.message).toMatch(
			/oauth\.accessToken\.defaultExpiresIn.*oauth\.accessToken\.maxExpiresIn/s,
		);
	});

	it("fails boot on a default read from the deprecated alias above the max", () => {
		const found = issues({ expiresIn: 3600, maxExpiresIn: 1800 });
		expect(found).toHaveLength(1);
		expect(found[0]?.message).toMatch(/oauth\.accessToken\.maxExpiresIn/);
		expect(found[0]?.message).toMatch(/oauth\.accessToken\.expiresIn/);
	});

	it("fails boot when neither the default nor its alias is set", () => {
		expect(issues({}).map((i) => i.path)).toContain("oauth.accessToken.defaultExpiresIn");
		expect(issues({ maxExpiresIn: 600 }).map((i) => i.path)).toContain(
			"oauth.accessToken.defaultExpiresIn",
		);
	});

	for (const key of ["defaultExpiresIn", "maxExpiresIn", "expiresIn"] as const) {
		for (const bad of [0, -1, 31_536_001, ""]) {
			it(`rejects ${key} = ${JSON.stringify(bad)} at that key`, () => {
				// `""` is the exported-but-empty environment variable, which
				// `z.coerce.number()` turns into 0: a token already expired.
				const found = issues({ defaultExpiresIn: 600, maxExpiresIn: 600, [key]: bad });
				expect(found.map((i) => i.path)).toContain(`oauth.accessToken.${key}`);
			});
		}
	}

	it("reports only the bad key, not a cross-field complaint built on it", () => {
		expect(issues({ defaultExpiresIn: 0, maxExpiresIn: 600 })).toHaveLength(1);
	});
});

describe("reference.conf and the lifetime environment variables", () => {
	const REFERENCE_CONF_PATH = fileURLToPath(
		new URL("../../../config/reference.conf", import.meta.url),
	);
	const REQUIRED_ENV = {
		OAUTH_JWT_SECRET: "access-token-lifetime.at-least-32-bytes.ok",
		OAUTH_JWT_ISSUER: "https://auth.test",
		SESSION_SECRET: "access-token-lifetime-session.at-least-32-bytes.ok",
	};

	function load(env: Record<string, string> = {}, applicationConf?: string) {
		const reference = parseFile(REFERENCE_CONF_PATH, { env: { ...REQUIRED_ENV, ...env } });
		const layered =
			applicationConf === undefined
				? reference
				: parseString(applicationConf, { env: { ...REQUIRED_ENV, ...env } }).withFallback(
						reference,
					);
		return validate(layered, AppConfigSchema);
	}

	it("ships a one-hour default and no extension past it", () => {
		const config = load();
		expect(resolveAccessTokenLifetime(config)).toEqual({
			defaultExpiresIn: 3600,
			maxExpiresIn: 3600,
		});
		expect(config.oauth.accessToken.expiresIn).toBe(3600);
	});

	it("still honours OAUTH_ACCESS_TOKEN_EXPIRES_IN as the default", () => {
		expect(resolveAccessTokenLifetime(load({ OAUTH_ACCESS_TOKEN_EXPIRES_IN: "900" }))).toEqual({
			defaultExpiresIn: 900,
			maxExpiresIn: 900,
		});
	});

	it("reads OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN, over the deprecated variable", () => {
		const config = load({
			OAUTH_ACCESS_TOKEN_EXPIRES_IN: "900",
			OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN: "600",
		});
		expect(resolveAccessTokenLifetime(config)).toEqual({
			defaultExpiresIn: 600,
			maxExpiresIn: 600,
		});
		expect(config.oauth.accessToken.expiresIn).toBe(600);
	});

	it("reads OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN", () => {
		expect(resolveAccessTokenLifetime(load({ OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN: "7200" }))).toEqual(
			{ defaultExpiresIn: 3600, maxExpiresIn: 7200 },
		);
	});

	it("fails boot when the default variable exceeds the max variable", () => {
		expect(() =>
			load({
				OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN: "7200",
				OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN: "3600",
			}),
		).toThrow(/defaultExpiresIn.*maxExpiresIn/s);
	});

	it("fails boot when a max below the shipped default is set without lowering the default", () => {
		expect(() => load({ OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN: "1800" })).toThrow(/maxExpiresIn/);
	});

	for (const name of [
		"OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN",
		"OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN",
		"OAUTH_ACCESS_TOKEN_EXPIRES_IN",
	]) {
		it(`fails boot on an exported-but-empty ${name} rather than reading it as zero`, () => {
			expect(() => load({ [name]: "" })).toThrow();
		});
	}

	it("keeps an application layer's override of the deprecated key deciding the default", () => {
		// The reason the shipped literal sits on `expiresIn`: a composition root
		// whose own layer still sets it (a scaffolded application.conf, say) must
		// not be silently outranked by a literal on the new key.
		const config = load({}, "oauth.accessToken.expiresIn = 900");
		expect(resolveAccessTokenLifetime(config)).toEqual({
			defaultExpiresIn: 900,
			maxExpiresIn: 900,
		});
		expect(config.oauth.accessToken.expiresIn).toBe(900);
	});

	it("lets an application layer's defaultExpiresIn outrank the shipped literal on the deprecated key", () => {
		const config = load({}, "oauth.accessToken { defaultExpiresIn = 300, maxExpiresIn = 1200 }");
		expect(resolveAccessTokenLifetime(config)).toEqual({
			defaultExpiresIn: 300,
			maxExpiresIn: 1200,
		});
		expect(config.oauth.accessToken.expiresIn).toBe(300);
	});
});
