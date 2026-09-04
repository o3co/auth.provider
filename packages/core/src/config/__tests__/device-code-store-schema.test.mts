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
 * #472 — the device-grant pair has to *reach* the modules that read it.
 *
 * `AppConfigSchema` is a strip-mode `z.object`, and the standalone validates
 * its HOCON against it before `buildModules` runs. Two sections were never
 * declared here, so a composition that mounted `deviceGrantModule` with
 * `redisDeviceCodeStoreModule` lost both at parse time, before either module's
 * own `configSchema` saw them: `redisDeviceCodeStore.keyPrefix` (the namespace
 * the redis README documents) and every key under `oauth.deviceAuthorization`
 * — `enabled` above all, so the grant the operator switched on stayed off.
 *
 * Presence-only, like `redisFederationTokenStore` (#456) and the other
 * `redis*` sections: the defaults stay in the device-grant package's
 * `reference.conf` and in the modules' `configSchema`s. The enum-shaped keys
 * keep their vocabulary so a typo fails here, by name, rather than as a
 * silently-absent declaration downstream.
 */
describe("redisDeviceCodeStore survives AppConfigSchema (#472)", () => {
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

describe("oauth.deviceAuthorization survives AppConfigSchema (#472)", () => {
	const base = makeValidAppConfig();

	it("keeps every key the device-grant module reads", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			oauth: {
				...base.oauth,
				deviceAuthorization: {
					enabled: true,
					"verification-uri": "https://example.com/device",
					"verification-uri-complete": false,
					"code-lifetime-seconds": 900,
					"polling-interval-seconds": 10,
					rateLimit: { limit: 5, windowSeconds: 300 },
				},
			},
		});
		expect(parsed.oauth.deviceAuthorization).toEqual({
			enabled: true,
			"verification-uri": "https://example.com/device",
			"verification-uri-complete": false,
			"code-lifetime-seconds": 900,
			"polling-interval-seconds": 10,
			rateLimit: { limit: 5, windowSeconds: 300 },
		});
	});

	it("keeps the declared-absence spelling for the store slot (#363)", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			oauth: { ...base.oauth, deviceAuthorization: { store: "unsupported" } },
		});
		expect(parsed.oauth.deviceAuthorization?.store).toBe("unsupported");
	});

	it("coerces the env-var spelling of the booleans, like every other env-overridable boolean (#288)", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			oauth: {
				...base.oauth,
				deviceAuthorization: { enabled: "true", "verification-uri-complete": "false" },
			},
		});
		expect(parsed.oauth.deviceAuthorization?.enabled).toBe(true);
		expect(parsed.oauth.deviceAuthorization?.["verification-uri-complete"]).toBe(false);
	});

	it("refuses a store declaration the slot does not have", () => {
		expect(() =>
			AppConfigSchema.parse({
				...base,
				oauth: { ...base.oauth, deviceAuthorization: { store: "memory" } },
			}),
		).toThrow();
	});

	it("is absent when omitted — the defaults live in the device-grant reference.conf", () => {
		expect(AppConfigSchema.parse(base).oauth.deviceAuthorization).toBeUndefined();
	});
});
