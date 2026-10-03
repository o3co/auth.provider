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
 * Each of core's own modules refuses an unknown key at every object level of
 * its own section, so a typo or a key an older version read refuses boot
 * naming its path instead of being dropped unread. The samples are core's
 * `reference.conf` as it resolves with no optional variable set, and samples
 * of their own for the levels the file leaves out, so every level each schema
 * declares is reached. The same guard holds every package's modules in
 * `tools/composition`.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import * as coreExports from "#/index.mjs";
import type { Module } from "#/modules/manifest/module-spec.mjs";
import { sectionStrictnessProblems } from "#/testing/sectionStrictness.mjs";

const REFERENCE_CONF_PATH = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

/** The substitutions `reference.conf` cannot resolve without. */
const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "section-strictness.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "section-strictness-session.at-least-32-bytes.ok",
};

/** Core's exported modules that declare a section. */
const CORE_SECTIONED: readonly Module[] = Object.values(coreExports).filter(
	(value): value is Module =>
		typeof value === "object" &&
		value !== null &&
		typeof (value as Module).name === "string" &&
		(value as Module).section !== undefined,
);

/** The levels of core's own sections whose keys are open by design, each with why. */
const CORE_EXEMPT: Readonly<Record<string, string>> = {
	"core-rate-limiter-memory.limits":
		"each key is a rate-limit prefix (`<prefix>:...`), named by the module that owns it or by the deployment",
};

describe("core's own modules refuse an unknown key at every level of their sections", () => {
	it("finds them: the JWKS module's and the in-process stores' among them (the guard is not vacuous)", () => {
		expect(CORE_SECTIONED.map((module) => module.name)).toEqual(
			expect.arrayContaining([
				"jwks",
				"core-challenge-store-memory",
				"core-federation-grant-store-memory",
				"core-mfa-transaction-store-memory",
				"core-rate-limiter-memory",
				"core-replay-seen-set-memory",
			]),
		);
	});

	it("keeps no unknown key in any of them", () => {
		const tree = parseFile(REFERENCE_CONF_PATH, { env: REQUIRED_ENV }).toObject();
		expect(
			sectionStrictnessProblems(CORE_SECTIONED, {
				tree,
				samples: {
					// The file sets no jwks key: each is bound to an unset variable.
					jwks: [{ path: "/keys/jwks.json", cacheMaxAge: "300" }],
					// The file declares no `limits` entry: one, so its level is reached.
					"core-rate-limiter-memory": [
						{
							maxBuckets: 10000,
							defaultLimit: { limit: 60, windowSeconds: 60 },
							limits: { login: { limit: 5, windowSeconds: 60 } },
						},
					],
				},
				exempt: CORE_EXEMPT,
			}),
		).toEqual([]);
	});
});
