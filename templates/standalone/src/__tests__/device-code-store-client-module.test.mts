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
 * `standaloneRedisClientsModule` provides `deviceCodeStoreClient`.
 *
 * The template does not mount the device grant, so nothing in `buildModules`
 * selects `redisDeviceCodeStoreModule` and the smoke test's client-slot
 * invariant cannot see it. This pins the slot directly: a deployment that adds
 * `deviceGrantModule` to this manifest and picks the Redis store must not hit
 * `missing-required-component` for a client slot the shared clients module
 * does not provide.
 */

import type { LifecycleRegistrar } from "@o3co/auth-provider-core";
import { redisDeviceCodeStoreModule } from "@o3co/auth-provider-redis";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const redisCtorCalls: Array<{ url: string }> = [];

vi.mock("ioredis", () => {
	class MockRedis {
		on = vi.fn();
		quit = vi.fn(async () => "OK" as const);
		ping = vi.fn(async () => "PONG" as const);
		eval = vi.fn();
		evalsha = vi.fn();
		duplicate(): MockRedis {
			return new MockRedis("redis://duplicate.local");
		}
		constructor(url: string) {
			redisCtorCalls.push({ url });
		}
	}
	return { Redis: MockRedis, default: MockRedis };
});

const importModule = async () => await import("../modules.mjs");

const baseConfig = {
	refreshTokenFamilyStore: {
		redis: { url: "redis://example.com:6379" },
	},
};

describe("standaloneRedisClientsModule.deviceCodeStoreClient", () => {
	beforeEach(() => {
		redisCtorCalls.length = 0;
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("provides every *Client slot redisDeviceCodeStoreModule requires", async () => {
		const { standaloneRedisClientsModule } = await importModule();
		const provided = new Set(Object.keys(standaloneRedisClientsModule.provides ?? {}));
		const required = [...(redisDeviceCodeStoreModule.requires ?? [])].filter((key) =>
			key.endsWith("Client"),
		);
		expect(required).toEqual(["deviceCodeStoreClient"]);
		expect(required.filter((key) => !provided.has(key))).toEqual([]);
	});

	it("resolves the client off the one shared socket, not a second connection", async () => {
		const { standaloneRedisClientsModule } = await importModule();
		const provides = (
			standaloneRedisClientsModule as unknown as {
				provides: Record<string, (deps: Record<string, unknown>) => Promise<unknown>>;
			}
		).provides;
		const lifecycleRegistrar: LifecycleRegistrar = { register: () => {} };

		const client = (await provides.deviceCodeStoreClient?.({
			config: { ...baseConfig },
			lifecycleRegistrar,
		})) as Record<string, unknown>;
		await provides.rateLimiterClient?.({ config: { ...baseConfig }, lifecycleRegistrar });

		expect(redisCtorCalls).toHaveLength(1);
		for (const method of ["create", "findPending", "decide", "poll", "remove"]) {
			expect(typeof client[method], `deviceCodeStoreClient.${method}`).toBe("function");
		}
	});
});
