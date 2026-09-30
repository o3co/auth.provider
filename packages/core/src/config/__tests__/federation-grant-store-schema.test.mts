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
 * Which modules provide the two federation-grant stores is a composition
 * root's choice, not core's: `federationGrantStore` and
 * `federationGrantIntentStore`, where the selections were, are presence-only,
 * kept as written so a root that parses with `AppConfigSchema` before boot
 * still hands them to the refusal of the paths they moved from.
 */
const base = makeValidAppConfig();

describe.each(["federationGrantStore", "federationGrantIntentStore"])(
	"%s, where the selection was",
	(key) => {
		it("is kept as written, whatever it holds: core reads nothing of it", () => {
			const parsed = AppConfigSchema.parse({ ...base, [key]: { adapter: "postgres" } });
			expect((parsed as Record<string, unknown>)[key]).toEqual({ adapter: "postgres" });
		});

		it("is absent when omitted", () => {
			expect((AppConfigSchema.parse(base) as Record<string, unknown>)[key]).toBeUndefined();
		});
	},
);
