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

import { BootError, createBootApp, defineModule } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redisSessionStoresModule } from "../src/modules/redisSessionStores.mjs";
import { makeIoredisRedisClient } from "./helpers/wrapper.mjs";

let container: StartedTestContainer;
let raw: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7-alpine").withExposedPorts(6379).start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 60_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

const minBoot = (extra: Record<string, unknown>) =>
	({
		...makeValidCoreConfig(),
		...extra,
	}) as never;

describe("redisSessionStoresModule manifest", () => {
	it("declares requires: redisClient + config", () => {
		expect(redisSessionStoresModule.requires).toEqual(["redisClient", "config"]);
	});

	it("provides 4 components", () => {
		const provides = redisSessionStoresModule.provides as Record<string, unknown>;
		expect(typeof provides.userSessionStore).toBe("function");
		expect(typeof provides.sessionRPRegistry).toBe("function");
		expect(typeof provides.sessionFamilyIndex).toBe("function");
		expect(typeof provides.sessionFederationIndex).toBe("function");
	});

	it("configSchema parses defaults under redisSessionStores key", () => {
		const parsed = redisSessionStoresModule.configSchema?.parse({});
		expect(
			(parsed as { redisSessionStores: { keyPrefix: string } }).redisSessionStores.keyPrefix,
		).toBe("ss:");
	});
});

describe("redisSessionStoresModule wiring", () => {
	it("createBootApp wires all 4 components against redisClient slot", async () => {
		// Activator pattern (no `activate` field on ModuleSpec): use contributes.routes
		// to force closure root inclusion, then read from handle.components after boot.
		const activator = defineModule({
			name: "activator",
			requires: [
				"userSessionStore",
				"sessionRPRegistry",
				"sessionFamilyIndex",
				"sessionFederationIndex",
			] as never,
			contributes: {
				routes: [
					{
						mountPath: "/__test_noop__",
						id: "test-noop",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					},
				],
			},
		});

		const handle = await createBootApp({
			modules: [redisSessionStoresModule, activator],
			bootstrapComponents: {
				config: minBoot({ redisSessionStores: { keyPrefix: "wire:" } }),
				redisClient: makeIoredisRedisClient(raw),
				pathResolver: (p: string) => p,
			} as never,
		});

		try {
			const components = handle.components as Record<string, unknown>;
			expect((components.userSessionStore as { kind: string }).kind).toBe("redis");
			expect((components.sessionRPRegistry as { kind: string }).kind).toBe("redis");
			expect((components.sessionFamilyIndex as { kind: string }).kind).toBe("redis");
			expect((components.sessionFederationIndex as { kind: string }).kind).toBe("redis");
		} finally {
			await handle.dispose();
		}
	});

	it("createBootApp throws BootError {missing-required-component} when redisClient absent", async () => {
		await expect(
			createBootApp({
				modules: [redisSessionStoresModule],
				bootstrapComponents: { config: minBoot({}) } as never,
			}),
		).rejects.toMatchObject({ name: "BootError", reason: "missing-required-component" });
	});
});
