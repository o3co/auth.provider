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
 * #561 — the consent step's adapter switch has a shared backend, and that
 * backend's namespace reaches its module.
 *
 * `consentStore.adapter` selects which module provides both consent slots in
 * a composition like the standalone; `"redis"` is the one
 * `deployment.mode = "multi"` accepts. `redisConsentStore` is presence-only,
 * like every `redis*` section: without it `AppConfigSchema`'s strip mode
 * drops the operator's namespace before the module's own `configSchema` runs,
 * and the default silently takes its place.
 */
const base = makeValidAppConfig();

describe("consentStore.adapter (#527, #561)", () => {
	it.each(["none", "memory", "redis"] as const)("accepts %s", (adapter) => {
		expect(AppConfigSchema.parse({ ...base, consentStore: { adapter } }).consentStore).toEqual({
			adapter,
		});
	});

	it("refuses an adapter it does not know, by name", () => {
		expect(() => AppConfigSchema.parse({ ...base, consentStore: { adapter: "postgres" } })).toThrow(
			/consentStore/,
		);
	});
});

describe("redisConsentStore survives AppConfigSchema (#561)", () => {
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
