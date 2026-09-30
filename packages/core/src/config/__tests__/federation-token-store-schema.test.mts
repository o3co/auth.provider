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
 * `federationTokenStore.type = "redis"` has to *reach* the composition root
 * before it can select anything, so the switch is declared. The Redis store's
 * own settings are its module's section, `redis-federation-token-store`,
 * which its schema parses; core keeps that section and the path it moved
 * from, `redisFederationTokenStore`, as written.
 */
describe("federationTokenStore and the Redis store's sections survive AppConfigSchema", () => {
	it("keeps the adapter switch", () => {
		const parsed = AppConfigSchema.parse({
			...makeValidAppConfig(),
			federationTokenStore: { type: "redis" },
		});
		expect(parsed.federationTokenStore?.type).toBe("redis");
	});

	it("accepts the memory adapter and refuses one that does not exist", () => {
		expect(
			AppConfigSchema.parse({ ...makeValidAppConfig(), federationTokenStore: { type: "memory" } })
				.federationTokenStore?.type,
		).toBe("memory");
		expect(() =>
			AppConfigSchema.parse({
				...makeValidAppConfig(),
				federationTokenStore: { type: "postgres" },
			}),
		).toThrow();
	});

	it("is absent when omitted — the default lives in reference.conf", () => {
		expect(AppConfigSchema.parse(makeValidAppConfig()).federationTokenStore).toBeUndefined();
	});

	it.each(["redis-federation-token-store", "redisFederationTokenStore"])(
		"keeps %s as written, encryption key included",
		(section) => {
			const written = {
				keyPrefix: "tenant-a:ft:",
				encryptionMode: "optional",
				encryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
			};
			const parsed = AppConfigSchema.parse({ ...makeValidAppConfig(), [section]: written });
			expect((parsed as Record<string, unknown>)[section]).toEqual(written);
		},
	);
});
