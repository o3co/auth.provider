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

import { createApp, defineModule, type SessionLifecycleStore } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { RedisDurability } from "#/clients.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { redisSessionStoresModule } from "#/modules/redisSessionStores.mjs";
import { testRedis } from "./support/redis.mjs";

let raw: Redis;

beforeAll(async () => {
	const at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	raw?.disconnect();
});

const minBoot = (extra: Record<string, unknown>) =>
	({
		...makeValidCoreConfig(),
		...extra,
	}) as never;

describe("redisSessionStoresModule manifest", () => {
	it("declares requires: 4 per-purpose client slots", () => {
		// The two subject slots are `requires`, not optional: filling neither
		// would leave `revokeAllForSubject` answering `unavailable` and
		// revoking nothing.
		expect(new Set(redisSessionStoresModule.requires)).toEqual(
			new Set([
				"userSessionStoreClient",
				"subjectSessionIndexClient",
				"subjectRevocationClient",
				"sessionLifecycleStoreClient",
			]),
		);
	});

	it("provides 4 components: the session record, the subject stores and the lifecycle store", () => {
		// The per-session stores (RP registry, family index, federation index)
		// are not provided: core's session lifecycle holds what they held.
		expect(new Set(Object.keys(redisSessionStoresModule.provides ?? {}))).toEqual(
			new Set([
				"userSessionStore",
				"subjectSessionIndex",
				"subjectRevocation",
				"sessionLifecycleStore",
			]),
		);
	});

	it("reads its own section, redis-session-stores, keyPrefix defaulting to ss:", () => {
		expect(redisSessionStoresModule).not.toHaveProperty("configSchema");
		expect(redisSessionStoresModule.section?.schema.parse(undefined)).toEqual({ keyPrefix: "ss:" });
	});
});

describe("redisSessionStoresModule wiring", () => {
	it("createApp wires the session record and the subject stores against per-purpose client slots", async () => {
		// Activator pattern (no `activate` field on ModuleSpec): use contributes.routes
		// to force closure root inclusion, then read from handle.components after boot.
		const activator = defineModule({
			name: "activator",
			requires: ["userSessionStore", "subjectSessionIndex", "subjectRevocation"] as never,
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

		const handle = await createApp({
			modules: [redisSessionStoresModule, activator],
			bootstrapComponents: {
				config: minBoot({ "redis-session-stores": { keyPrefix: "wire:" } }),
				pathResolver: (p: string) => p,
				// Spread every per-purpose wrapper; the module consumes its 4.
				...makeIoredisClients(raw),
			} as never,
		});

		try {
			const components = handle.components as Record<string, unknown>;
			expect((components.userSessionStore as { kind: string }).kind).toBe("redis");
			expect((components.subjectSessionIndex as { kind: string }).kind).toBe("redis");
			expect((components.subjectRevocation as { kind: string }).kind).toBe("redis");
		} finally {
			await handle.dispose();
		}
	});

	it("createApp throws BootError {missing-required-component} when per-purpose client slots absent", async () => {
		await expect(
			createApp({
				modules: [redisSessionStoresModule],
				bootstrapComponents: { config: minBoot({}) } as never,
			}),
		).rejects.toMatchObject({ name: "BootError", reason: "missing-required-component" });
	});
});

describe("redisSessionStoresModule's session lifecycle store", () => {
	/** Brings `sessionLifecycleStore` into the boot, as a module that reads it would. */
	const reader = defineModule({
		name: "lifecycle-reader",
		requires: ["sessionLifecycleStore"] as never,
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

	const report = (maxmemoryPolicy: string | undefined, refusal?: unknown): RedisDurability => ({
		maxmemoryPolicy,
		appendOnly: true,
		snapshots: undefined,
		refusal,
	});

	/** The shared clients, the lifecycle client's server answering `durability` with `answer`. */
	const clientsReporting = (answer: () => Promise<RedisDurability>) => {
		const clients = makeIoredisClients(raw);
		return {
			...clients,
			sessionLifecycleStoreClient: { ...clients.sessionLifecycleStoreClient, durability: answer },
		};
	};

	it("provides a store over real Redis, its keys under the section's keyPrefix and lc:", async () => {
		const handle = await createApp({
			modules: [redisSessionStoresModule, reader],
			bootstrapComponents: {
				config: minBoot({ "redis-session-stores": { keyPrefix: "lcwire:" } }),
				pathResolver: (p: string) => p,
				...makeIoredisClients(raw),
			} as never,
		});
		try {
			const store = (handle.components as { sessionLifecycleStore?: SessionLifecycleStore })
				.sessionLifecycleStore;
			if (store === undefined) throw new Error("the module provided no sessionLifecycleStore");
			const expiresAt = new Date(Date.now() + 60_000);
			expect(await store.open("sid-lc-1", "sub-1", expiresAt)).toEqual({ outcome: "opened" });
			expect((await store.read("sid-lc-1"))?.value).toMatchObject({
				sub: "sub-1",
				state: "active",
			});
			const keys = await raw.keys("lcwire:*");
			expect(keys.length).toBeGreaterThan(0);
			for (const key of keys) expect(key.startsWith("lcwire:lc:"), key).toBe(true);
			expect(keys.some((key) => key.startsWith("lcwire:lc:{lc:"))).toBe(true);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses the boot on a server that may evict, naming the module and the store", async () => {
		const refused = createApp({
			modules: [redisSessionStoresModule, reader],
			bootstrapComponents: {
				config: minBoot({}),
				pathResolver: (p: string) => p,
				...clientsReporting(async () => report("volatile-lru")),
			} as never,
		});
		await expect(refused).rejects.toMatchObject({
			name: "BootError",
			reason: "provides-factory-failed",
			details: { module: "redis-session-stores", componentKey: "sessionLifecycleStore" },
			cause: {
				name: "RedisStoreEvictableError",
				reason: "session-lifecycle-store-evictable",
				maxmemoryPolicy: "volatile-lru",
			},
		});
	});

	it("refuses the boot on a policy it cannot read, and boots when the clients assume noeviction", async () => {
		const unread = async () => report(undefined, new Error("NOPERM"));
		await expect(
			createApp({
				modules: [redisSessionStoresModule, reader],
				bootstrapComponents: {
					config: minBoot({}),
					pathResolver: (p: string) => p,
					...clientsReporting(unread),
				} as never,
			}),
		).rejects.toMatchObject({
			reason: "provides-factory-failed",
			cause: { reason: "session-lifecycle-store-evictable", maxmemoryPolicy: undefined },
		});
		const handle = await createApp({
			modules: [redisSessionStoresModule, reader],
			bootstrapComponents: {
				config: minBoot({}),
				pathResolver: (p: string) => p,
				...clientsReporting(async () => ({ ...(await unread()), assumeNoEviction: true })),
			} as never,
		});
		await handle.dispose();
	});
});
