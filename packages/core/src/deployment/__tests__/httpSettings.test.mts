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
 * The `httpSettings` slot: what every module's HTTP behaviour
 * depends on of the `http` module's settings — which forwarding hops
 * `req.ip` trusts, and the origins core's CORS middleware lets read: the
 * slot's shape, its wiring between modules, and the test double. The slot's
 * contract suite is the test kit's, and runs over this double there.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { MAX_TRUST_PROXY_HOPS } from "#/config/application.schema.mjs";
import type { HttpSettings } from "#/deployment/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestHttpSettings } from "#/testing/index.mjs";

describe("the httpSettings slot", () => {
	it("is optional, and holds what every module's HTTP behaviour depends on", () => {
		expectTypeOf<ComponentMap["httpSettings"]>().toEqualTypeOf<HttpSettings | undefined>();
		expectTypeOf<ProviderDeps<"httpSettings">["httpSettings"]>().toEqualTypeOf<HttpSettings>();
		expectTypeOf<HttpSettings["trustProxy"]>().toEqualTypeOf<
			boolean | number | readonly string[]
		>();
		expectTypeOf<HttpSettings["cors"]>().toEqualTypeOf<{
			readonly allowedOrigins: readonly string[];
		}>();
		expect(MAX_TRUST_PROXY_HOPS).toBe(255);
	});

	it("is filled by a module, and read by another", async () => {
		const settings = createTestHttpSettings();
		let seen: HttpSettings | undefined;
		const owner = defineModule({
			name: "test:http-settings-owner",
			provides: { httpSettings: () => settings },
		});
		const reader = defineModule({
			name: "test:http-settings-reader",
			requires: ["httpSettings"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.httpSettings;
						return {
							id: "test-http-settings-reader",
							mountPath: "/__test_http_settings_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [owner, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen).toBe(settings);
		} finally {
			await handle.dispose();
		}
	});
});

describe("createTestHttpSettings", () => {
	it("trusts no forwarding hop and lets no origin read, unless told otherwise", () => {
		expect(createTestHttpSettings()).toStrictEqual({
			trustProxy: false,
			cors: { allowedOrigins: [] },
		});
		expect(createTestHttpSettings({ trustProxy: 1 }).trustProxy).toBe(1);
	});
});
