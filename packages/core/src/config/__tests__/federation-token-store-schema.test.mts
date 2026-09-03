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
 * #456 — `federationTokenStore.type = "redis"` has to *reach* the composition
 * root before it can select anything.
 *
 * The standalone validates its HOCON against `AppConfigSchema` before
 * `buildModules` runs, and a top-level `z.object` strips keys it does not
 * know. `federationTokenStore` was never declared here, so the switch the
 * README documented was dropped at parse time — and the module-internal
 * `redisFederationTokenStore.*` section (the encryption key above all) went
 * the same way, exactly the trap `redisSessionStores` / `redisAccessTokenDenylist`
 * already paid for. Presence-only, like those: the defaults stay in
 * `reference.conf` and in `redisFederationTokenStoreModule.configSchema`.
 */
describe("federationTokenStore / redisFederationTokenStore survive AppConfigSchema (#456)", () => {
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

	it("keeps the Redis module's section, encryption key included", () => {
		const parsed = AppConfigSchema.parse({
			...makeValidAppConfig(),
			redisFederationTokenStore: {
				keyPrefix: "tenant-a:ft:",
				encryptionMode: "required",
				encryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
			},
		});
		expect(parsed.redisFederationTokenStore).toEqual({
			keyPrefix: "tenant-a:ft:",
			encryptionMode: "required",
			encryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		});
	});

	it("refuses an encryption mode the store does not have", () => {
		expect(() =>
			AppConfigSchema.parse({
				...makeValidAppConfig(),
				redisFederationTokenStore: { encryptionMode: "optional" },
			}),
		).toThrow();
	});
});
