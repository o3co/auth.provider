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
 * Which module provides the consent slots is a composition root's choice, not
 * core's: `consentStore`, where the selection was, is presence-only, kept as
 * written so a root that parses with `AppConfigSchema` before boot still hands
 * it to the refusal of the path it moved from. `redisConsentStore` is
 * presence-only too, like every `redis*` section.
 */
const base = makeValidAppConfig();

describe("consentStore, where the selection was", () => {
	it("is kept as written, whatever it holds: core reads nothing of it", () => {
		expect(
			AppConfigSchema.parse({ ...base, consentStore: { adapter: "postgres" } }).consentStore,
		).toEqual({ adapter: "postgres" });
	});

	it("is absent when omitted", () => {
		expect(AppConfigSchema.parse(base).consentStore).toBeUndefined();
	});
});

describe("redisConsentStore survives AppConfigSchema", () => {
	it("keeps the Redis module's key namespace", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			redisConsentStore: { keyPrefix: "tenant-a:consent:" },
		});
		expect(parsed.redisConsentStore).toEqual({ keyPrefix: "tenant-a:consent:" });
	});

	it("is absent when omitted — the default lives in the module", () => {
		expect(AppConfigSchema.parse(base).redisConsentStore).toBeUndefined();
	});
});
