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
 * The Redis device-code store's section has to *reach* its module.
 * `AppConfigSchema` is a strip-mode `z.object`, so a root that parses its
 * configuration with it before boot would lose an undeclared section — here
 * `redisDeviceCodeStore.keyPrefix`, the namespace the redis README documents.
 *
 * Presence-only, like the other `redis*` sections: the default stays with the
 * module.
 */
describe("redisDeviceCodeStore survives AppConfigSchema", () => {
	it("keeps the Redis module's key namespace", () => {
		const parsed = AppConfigSchema.parse({
			...makeValidAppConfig(),
			redisDeviceCodeStore: { keyPrefix: "tenant-a:devauth:" },
		});
		expect(parsed.redisDeviceCodeStore).toEqual({ keyPrefix: "tenant-a:devauth:" });
	});

	it("is absent when omitted — the default lives in the module", () => {
		expect(AppConfigSchema.parse(makeValidAppConfig()).redisDeviceCodeStore).toBeUndefined();
	});
});
