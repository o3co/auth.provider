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
import { AdapterFactoryError } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import { createSessionStoreFactory, registerBuiltinSessionStores } from "#/store/factory.mjs";

// The redis builder dynamically imports "redis" and "connect-redis" and then
// calls client.connect(). Mock them so tests don't touch a real Redis server.
vi.mock("redis", () => ({
	createClient: vi.fn((opts: { url?: string; password?: string }) => ({
		__mock: "redis-client",
		__opts: opts,
		connect: vi.fn().mockResolvedValue(undefined),
		ping: vi.fn().mockResolvedValue("PONG"),
	})),
}));

vi.mock("connect-redis", () => ({
	RedisStore: class MockRedisStore {
		public readonly client: unknown;
		constructor(opts: { client: unknown }) {
			this.client = opts.client;
		}
		get(_sid: string): unknown {
			return undefined;
		}
		set(): void {}
		destroy(): void {}
	},
}));

describe("SessionStoreFactory", () => {
	it("returns undefined for the memory adapter (express-session in-memory default)", async () => {
		const factory = createSessionStoreFactory();
		registerBuiltinSessionStores(factory);

		const store = await factory.create({ type: "memory" });
		expect(store).toBeUndefined();
	});

	it("returns a RedisStore for the redis adapter", async () => {
		const factory = createSessionStoreFactory();
		registerBuiltinSessionStores(factory);

		const store = await factory.create({
			type: "redis",
			url: "redis://localhost:6379",
		});
		expect(store).toBeDefined();
		// structural: must look like a session store
		expect(typeof (store as unknown as { get?: unknown }).get).toBe("function");
	});

	it("passes url and password through to the redis client", async () => {
		const factory = createSessionStoreFactory();
		registerBuiltinSessionStores(factory);

		const store = await factory.create({
			type: "redis",
			url: "redis://example.com:6379",
			password: "s3cret",
		});
		const client = (store as unknown as { client: { __opts: { url?: string; password?: string } } })
			.client;
		expect(client.__opts.url).toBe("redis://example.com:6379");
		expect(client.__opts.password).toBe("s3cret");
	});

	it("registers only 'redis' and 'memory' as built-ins", () => {
		const factory = createSessionStoreFactory();
		registerBuiltinSessionStores(factory);
		expect(factory.registeredTypes().sort()).toEqual(["memory", "redis"]);
	});

	it("throws AdapterFactoryError for unregistered session store type", async () => {
		const factory = createSessionStoreFactory();
		registerBuiltinSessionStores(factory);

		try {
			await factory.create({ type: "memcached" });
			throw new Error("should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(AdapterFactoryError);
			const e = err as AdapterFactoryError;
			expect(e.reason).toBe("unknown");
			expect(e.kind).toBe("SessionStore");
			expect(e.type).toBe("memcached");
			expect([...e.registered].sort()).toEqual(["memory", "redis"]);
		}
	});

	it("redis builder throws a clear error when url is missing", async () => {
		const factory = createSessionStoreFactory();
		registerBuiltinSessionStores(factory);
		await expect(factory.create({ type: "redis" })).rejects.toThrow(/url/);
	});

	it("registers a readiness probe for the redis client it opens", async () => {
		// The client never leaves the builder — the returned RedisStore is a
		// connect-redis object, not a connection — so the probe has to be
		// registered here or readiness has nothing to ping.
		const probes: Array<{ name: string; check: () => Promise<unknown> }> = [];
		const factory = createSessionStoreFactory({ readiness: { register: (p) => probes.push(p) } });
		registerBuiltinSessionStores(factory);

		await factory.create({ type: "redis", url: "redis://localhost:6379" });

		expect(probes.map((p) => p.name)).toEqual(["session-store"]);
		await expect(probes[0]?.check()).resolves.toBe("PONG");
	});

	it("registers no readiness probe for the memory adapter", async () => {
		const probes: Array<{ name: string; check: () => Promise<unknown> }> = [];
		const factory = createSessionStoreFactory({ readiness: { register: (p) => probes.push(p) } });
		registerBuiltinSessionStores(factory);

		await factory.create({ type: "memory" });

		expect(probes).toEqual([]);
	});
});
