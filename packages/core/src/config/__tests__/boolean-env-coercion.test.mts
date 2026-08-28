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
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * #288 — every env-overridable boolean rides ONE coercion path.
 *
 * HOCON substitutes `${?VAR}` as a **string**, always. Before this suite the
 * schema had two paths: `coerceBooleanFromEnv` on two fields, and a bare
 * `z.boolean()` on the rest that only ever worked because `@o3co/ts.hocon`'s
 * zod bridge coerces a bare boolean leaf **it can reach**. The bridge walks
 * `ZodObject` shapes and unwraps optional/nullable/default/catch/readonly —
 * and stops at anything else. A `z.preprocess(...)` wrapper (a `ZodPipe`) is
 * opaque to it, which is exactly what happened to `oauth.jwt`: the section is
 * wrapped to catch legacy flat fields, so `OAUTH_JWT_LEGACY_TYP_ACCEPT`
 * reached `z.boolean()` as a string and **failed boot**.
 *
 * These tests pin the coercion at the field, not at the bridge, so wrapping a
 * section tomorrow cannot silently take an operator's documented override away.
 */

/** Every boolean in `AppConfigSchema` that a `${?VAR}` can reach. */
const ENV_OVERRIDABLE_BOOLEANS = [
	{
		key: "session.secure",
		envVar: "SESSION_SECURE",
		set: (config: Record<string, unknown>, value: unknown) => {
			(config.session as Record<string, unknown>).secure = value;
		},
		read: (parsed: Record<string, unknown>) => (parsed.session as Record<string, unknown>).secure,
	},
	{
		key: "oauth.jwt.legacyTypAccept",
		envVar: "OAUTH_JWT_LEGACY_TYP_ACCEPT",
		set: (config: Record<string, unknown>, value: unknown) => {
			((config.oauth as Record<string, unknown>).jwt as Record<string, unknown>).legacyTypAccept =
				value;
		},
		read: (parsed: Record<string, unknown>) =>
			((parsed.oauth as Record<string, unknown>).jwt as Record<string, unknown>).legacyTypAccept,
	},
	{
		key: "oauth.requireEmailVerified",
		envVar: "OAUTH_REQUIRE_EMAIL_VERIFIED",
		set: (config: Record<string, unknown>, value: unknown) => {
			(config.oauth as Record<string, unknown>).requireEmailVerified = value;
		},
		read: (parsed: Record<string, unknown>) =>
			(parsed.oauth as Record<string, unknown>).requireEmailVerified,
	},
	{
		key: "oauth.resourceIndicator.enabled",
		envVar: "OAUTH_RESOURCE_INDICATOR_ENABLED",
		set: (config: Record<string, unknown>, value: unknown) => {
			(config.oauth as Record<string, unknown>).resourceIndicator = { enabled: value };
		},
		read: (parsed: Record<string, unknown>) =>
			((parsed.oauth as Record<string, unknown>).resourceIndicator as Record<string, unknown>)
				?.enabled,
	},
	{
		key: "federations.<name>.enabled",
		envVar: "FEDERATIONS_GOOGLE_ENABLED",
		set: (config: Record<string, unknown>, value: unknown) => {
			config.federations = { google: { enabled: value } };
		},
		read: (parsed: Record<string, unknown>) =>
			(
				(parsed.federations as Record<string, Record<string, unknown>>).google as Record<
					string,
					unknown
				>
			).enabled,
	},
] as const;

/**
 * The accepted spellings. Narrow on purpose: an unrecognised string is a
 * misconfiguration, and boot failing on it beats an operator's `enabled=ture`
 * silently reading as `true` (which is what `z.coerce.boolean()` would do —
 * it is `Boolean(value)`, so every non-empty string is `true`, `"false"`
 * included).
 *
 * `""` is the exported-but-empty shape a `.env` file, a compose
 * `environment:` entry or a blank ConfigMap key produces. It reads as `false`,
 * matching what `normalizeTrustProxy` already decided for `HTTP_TRUST_PROXY`
 * in #292.
 */
const COERCIONS: ReadonlyArray<[unknown, boolean]> = [
	["true", true],
	["TRUE", true],
	["1", true],
	[" true ", true],
	["false", false],
	["FALSE", false],
	["0", false],
	["", false],
	[true, true],
	[false, false],
];

/** Strings that must NOT be guessed at. */
const REJECTED: ReadonlyArray<unknown> = ["yes", "no", "on", "off", "ture", "2", 42, null];

function configWith(
	field: (typeof ENV_OVERRIDABLE_BOOLEANS)[number],
	value: unknown,
): Record<string, unknown> {
	const config = makeValidAppConfig() as unknown as Record<string, unknown>;
	field.set(config, value);
	return config;
}

describe("#288: every env-overridable boolean uses one coercion path", () => {
	for (const field of ENV_OVERRIDABLE_BOOLEANS) {
		describe(`${field.key} (${field.envVar})`, () => {
			for (const [input, expected] of COERCIONS) {
				it(`coerces ${JSON.stringify(input)} to ${expected}`, () => {
					const result = AppConfigSchema.safeParse(configWith(field, input));
					expect(result.success, result.success ? "" : JSON.stringify(result.error.issues)).toBe(
						true,
					);
					if (!result.success) return;
					expect(field.read(result.data as unknown as Record<string, unknown>)).toBe(expected);
				});
			}

			for (const input of REJECTED) {
				it(`rejects ${JSON.stringify(input)} rather than guessing`, () => {
					const result = AppConfigSchema.safeParse(configWith(field, input));
					expect(result.success).toBe(false);
				});
			}

			it("names the accepted spellings when it rejects", () => {
				const result = AppConfigSchema.safeParse(configWith(field, "on"));
				expect(result.success).toBe(false);
				if (result.success) return;
				expect(result.error.issues.map((issue) => issue.message).join("\n")).toMatch(
					/true.*false.*1.*0/s,
				);
			});
		});
	}

	it("still refuses sameSite=none with a coerced secure=false", () => {
		// The #282 guard reads the COERCED value, so it has to keep firing for
		// the string form an env var actually delivers.
		const config = makeValidAppConfig() as unknown as Record<string, unknown>;
		const session = config.session as Record<string, unknown>;
		session.secure = "false";
		session.sameSite = "none";
		const result = AppConfigSchema.safeParse(config);
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.issues.map((issue) => issue.message).join("\n")).toMatch(
			/SESSION_SECURE=true/,
		);
	});

	it("leaves an omitted optional boolean undefined rather than defaulting it", () => {
		// The defaults live in reference.conf (ADR 2026-04-30), so the schema
		// must not invent one when the key is absent.
		const parsed = AppConfigSchema.parse(makeValidAppConfig());
		expect(parsed.oauth.jwt.legacyTypAccept).toBeUndefined();
		expect(parsed.oauth.requireEmailVerified).toBeUndefined();
	});
});
