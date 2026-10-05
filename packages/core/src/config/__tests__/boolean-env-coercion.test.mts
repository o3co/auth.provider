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
 * Every env-overridable boolean rides ONE coercion path, pinned at the field.
 *
 * HOCON substitutes `${?VAR}` as a **string**, always. `@o3co/ts.hocon`'s zod
 * bridge coerces only a bare boolean leaf **it can reach**: it walks
 * `ZodObject` shapes and unwraps optional/nullable/default/catch/readonly, and
 * a `z.preprocess(...)` wrapper (a `ZodPipe`) is opaque to it. `oauth.jwt` is
 * wrapped to catch legacy flat fields, so a bare `z.boolean()` there would get
 * `OAUTH_JWT_LEGACY_TYP_ACCEPT` as a string and **fail boot**. Coercing at the
 * field, not at the bridge, means wrapping a section cannot silently take an
 * operator's documented override away.
 */

/** The `google` federation `parsed` holds under `core.federations`. */
const federationOf = (parsed: Record<string, unknown>): Record<string, unknown> =>
	((parsed.core as { federations: Record<string, Record<string, unknown>> }).federations
		.google as Record<string, unknown>) ?? {};

/** Every boolean in `AppConfigSchema` that a `${?VAR}` can reach. */
const ENV_OVERRIDABLE_BOOLEANS = [
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
		key: "core.federations.<name>.enabled",
		envVar: "CORE_FEDERATIONS_GOOGLE_ENABLED",
		set: (config: Record<string, unknown>, value: unknown) => {
			config.core = {
				...(config.core as object),
				federations: { google: { enabled: value, type: "google" } },
			};
		},
		read: (parsed: Record<string, unknown>) => federationOf(parsed).enabled,
	},
	{
		// Whether a federation's upstream `amr` counts (ADR
		// 2026-09-25-multi-factor-authentication). No environment variable is
		// wired for it — no bundled adapter surfaces an upstream `amr`, and it
		// is set in config beside `enabled` — but it is coerced as every
		// boolean here is, so a `${?VAR}` an operator adds reads the same way.
		key: "core.federations.<name>.trustUpstreamAmr",
		envVar: "no variable wired; set in config",
		set: (config: Record<string, unknown>, value: unknown) => {
			config.core = {
				...(config.core as object),
				federations: { google: { enabled: true, type: "google", trustUpstreamAmr: value } },
			};
		},
		read: (parsed: Record<string, unknown>) => federationOf(parsed).trustUpstreamAmr,
	},
] as const;

/**
 * The accepted spellings. Narrow on purpose: an unrecognised string is a
 * misconfiguration, and boot failing on it beats an operator's `enabled=ture`
 * silently reading as `true`, as `z.coerce.boolean()` (`Boolean(value)`) reads
 * every non-empty string, `"false"` included.
 *
 * `""` is the exported-but-empty shape a `.env` file, a compose `environment:`
 * entry or a blank ConfigMap key produces. It reads as `false`, as
 * `normalizeTrustProxy` reads it for `HTTP_TRUST_PROXY`.
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

describe("every env-overridable boolean uses one coercion path", () => {
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

	it("leaves an omitted optional boolean undefined rather than defaulting it", () => {
		// The defaults live in reference.conf (ADR 2026-04-30), so the schema
		// must not invent one when the key is absent.
		const parsed = AppConfigSchema.parse(makeValidAppConfig());
		expect(parsed.oauth.jwt.legacyTypAccept).toBeUndefined();
		expect(parsed.oauth.requireEmailVerified).toBeUndefined();
	});
});
