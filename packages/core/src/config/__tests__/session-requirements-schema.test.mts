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
 * `sessionRequirements.expected` (the session-admission ADR's D7): the
 * requirement names a composition expects, a list of strings with no
 * default in the schema or in `reference.conf` — a composition that
 * installs a consumer of admission writes it, and boot compares it with
 * what registered.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { AppConfigSchema, CoreConfigSchema } from "#/config/application.schema.mjs";
import { makeValidAppConfig, makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const REFERENCE_CONF = fileURLToPath(new URL("../../../config/reference.conf", import.meta.url));

const ENV = {
	OAUTH_JWT_SECRET: "session-requirements-schema-test.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "session-requirements-schema-test-session.at-least-32-bytes.ok",
};

const issuesAt = (result: { success: boolean; error?: { issues: { path: PropertyKey[] }[] } }) =>
	result.success ? [] : (result.error?.issues ?? []).map((issue) => issue.path.join("."));

describe("sessionRequirements.expected (D7)", () => {
	it("has no default: reference.conf carries none, and a configuration without the section parses to none", () => {
		const fromReference = validate(parseFile(REFERENCE_CONF, { env: ENV }), AppConfigSchema);
		expect(fromReference.sessionRequirements).toBeUndefined();
		const { sessionRequirements: _none, ...without } = makeValidCoreConfig() as Record<
			string,
			unknown
		>;
		expect(
			(CoreConfigSchema.parse(without) as { sessionRequirements?: unknown }).sessionRequirements,
		).toBeUndefined();
	});

	it("reads a list of requirement names, empty allowed", () => {
		for (const expected of [[], ["mfa"], ["mfa", "risk"]]) {
			const parsed = CoreConfigSchema.parse({
				...makeValidCoreConfig(),
				sessionRequirements: { expected },
			}) as { sessionRequirements?: { expected: readonly string[] } };
			expect(parsed.sessionRequirements?.expected).toEqual(expected);
		}
	});

	it("refuses what is not a list of non-empty strings, and a section without the list, naming the key", () => {
		for (const expected of ["mfa", [""], [7], null, undefined]) {
			expect(
				issuesAt(
					CoreConfigSchema.safeParse({
						...makeValidCoreConfig(),
						sessionRequirements: { expected },
					}),
				),
				JSON.stringify(expected),
			).toContain("sessionRequirements.expected");
		}
	});

	it("survives AppConfigSchema, which the standalone parses through", () => {
		const parsed = AppConfigSchema.parse({
			...makeValidAppConfig(),
			sessionRequirements: { expected: ["mfa"] },
		});
		expect(parsed.sessionRequirements?.expected).toEqual(["mfa"]);
	});

	it("is declared by the test fixtures as expecting nothing: every createApp test that installs a consumer states its posture", () => {
		expect(makeValidCoreConfig().sessionRequirements).toEqual({ expected: [] });
		expect(makeValidAppConfig().sessionRequirements).toEqual({ expected: [] });
	});
});
