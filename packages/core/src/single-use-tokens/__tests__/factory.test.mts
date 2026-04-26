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
import {
	createSingleUseTokenStoreFactory,
	registerBuiltinSingleUseTokenStores,
} from "#/single-use-tokens/factory.mjs";
import { createFakeRedis } from "./fakeRedis.mjs";

describe("createSingleUseTokenStoreFactory", () => {
	it("creates a factory with no adapters registered initially", () => {
		const factory = createSingleUseTokenStoreFactory();
		expect(factory.registeredTypes()).toEqual([]);
	});

	it("registerBuiltinSingleUseTokenStores adds memory + redis", () => {
		const factory = createSingleUseTokenStoreFactory();
		registerBuiltinSingleUseTokenStores(factory);
		expect(factory.registeredTypes().sort()).toEqual(["memory", "redis"]);
	});

	it("can resolve the memory adapter", async () => {
		const factory = createSingleUseTokenStoreFactory();
		registerBuiltinSingleUseTokenStores(factory);
		const store = await factory.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});

	it("can resolve the redis adapter when a client is provided", async () => {
		const factory = createSingleUseTokenStoreFactory();
		registerBuiltinSingleUseTokenStores(factory);
		const store = await factory.create({ type: "redis", client: createFakeRedis() });
		expect(store.kind).toBe("redis");
	});

	it("redis adapter rejects when client is missing", async () => {
		const factory = createSingleUseTokenStoreFactory();
		registerBuiltinSingleUseTokenStores(factory);
		await expect(factory.create({ type: "redis" })).rejects.toThrow(/client/);
	});

	it("supports consumer-registered adapters", async () => {
		const factory = createSingleUseTokenStoreFactory();
		registerBuiltinSingleUseTokenStores(factory);
		factory.register("custom", () => ({
			kind: "custom",
			async issue() {},
			async consume() {
				return { outcome: "unknown" } as const;
			},
			async markSeen() {
				return { outcome: "fresh" } as const;
			},
		}));
		const store = await factory.create({ type: "custom" });
		expect(store.kind).toBe("custom");
	});
});
