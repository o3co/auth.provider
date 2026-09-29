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
 * The `httpSettings` slot (#728): what every module's HTTP behaviour
 * depends on of the `http` module's settings — which forwarding hops
 * `req.ip` trusts, and the origins core's CORS middleware lets read. Its
 * contract suite and the test double: the double keeps every case, and
 * each way the settings can break the contract fail the case that names it.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { MAX_TRUST_PROXY_HOPS } from "#/config/application.schema.mjs";
import type { HttpSettings } from "#/deployment/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	createTestHttpSettings,
	type HttpSettingsContractInput,
	httpSettingsContract,
} from "#/testing/index.mjs";

const RULES = {
	trustProxy:
		"trustProxy is what Express's trust proxy takes: true or false, a hop count from 0 to 255, or a non-empty list of addresses, ranges and named ranges",
	cors: "cors.allowedOrigins lists serialized origins: a scheme, a host and a port that is not the scheme's default",
	frozen: "the settings are frozen, the lists too",
} as const;

/** The names of the cases `build` fails. */
const failing = async (build: HttpSettingsContractInput["build"]): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of httpSettingsContract({ build })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

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

describe("httpSettingsContract — the double", () => {
	const cases = httpSettingsContract({ build: () => createTestHttpSettings() });

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([RULES.trustProxy, RULES.cors, RULES.frozen]);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});

	it("keeps them for each shape trustProxy takes, and origins a deployment lists", async () => {
		for (const trustProxy of [
			true,
			false,
			0,
			2,
			255,
			["loopback", "10.0.0.0/8", "192.0.2.7", "::1"],
		] as const) {
			expect(
				await failing(() =>
					createTestHttpSettings({
						trustProxy,
						allowedOrigins: ["https://app.example.com", "http://localhost:5173"],
					}),
				),
			).toEqual([]);
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

describe("httpSettingsContract — each way the settings can break it", () => {
	it("a trustProxy Express would not read as meant", async () => {
		for (const trustProxy of [
			-1,
			1.5,
			256,
			[],
			["10.0.0.0/33"],
			["not-an-address"],
			"true",
			"1",
		] as const) {
			expect(
				await failing(() =>
					createTestHttpSettings({
						trustProxy: trustProxy as unknown as HttpSettings["trustProxy"],
					}),
				),
			).toEqual([RULES.trustProxy]);
		}
	});

	it("an allowed origin that is not a string", async () => {
		expect(
			await failing(() => createTestHttpSettings({ allowedOrigins: [42 as unknown as string] })),
		).toEqual([RULES.cors]);
	});

	it("an allowed origin that is not one: a trailing slash, a path, a wildcard, a default port", async () => {
		for (const origin of [
			"https://app.example.com/",
			"https://app.example.com/app",
			"*",
			"https://app.example.com:443",
			"app.example.com",
		]) {
			expect(await failing(() => createTestHttpSettings({ allowedOrigins: [origin] }))).toEqual([
				RULES.cors,
			]);
		}
	});

	it("settings a reader could change under the others", async () => {
		const base = createTestHttpSettings({ trustProxy: ["loopback"] });
		expect(await failing(() => ({ ...base }))).toEqual([RULES.frozen]);
		expect(
			await failing(() => Object.freeze({ ...base, cors: { allowedOrigins: Object.freeze([]) } })),
		).toEqual([RULES.frozen]);
		expect(
			await failing(() =>
				Object.freeze({ ...base, cors: Object.freeze({ allowedOrigins: [] as string[] }) }),
			),
		).toEqual([RULES.frozen]);
		expect(
			await failing(() => Object.freeze({ ...base, trustProxy: ["loopback"] as string[] })),
		).toEqual([RULES.frozen]);
	});
});
