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

import {
	createApp,
	defineModule,
	type Logger,
	type SessionFamilyIndex,
	type SessionLifecycleStore,
	supportsSessionEnd,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
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
	it("declares requires: 7 per-purpose client slots", () => {
		// The two subject slots are `requires`, not optional: filling neither
		// would leave `revokeAllForSubject` answering `unavailable` and
		// revoking nothing.
		expect(new Set(redisSessionStoresModule.requires)).toEqual(
			new Set([
				"userSessionStoreClient",
				"sessionRPRegistryClient",
				"sessionFamilyIndexClient",
				"sessionFederationIndexClient",
				"subjectSessionIndexClient",
				"subjectRevocationClient",
				"sessionLifecycleStoreClient",
			]),
		);
	});

	it("provides 7 components", () => {
		const provides = redisSessionStoresModule.provides as Record<string, unknown>;
		expect(typeof provides.userSessionStore).toBe("function");
		expect(typeof provides.sessionRPRegistry).toBe("function");
		expect(typeof provides.sessionFamilyIndex).toBe("function");
		expect(typeof provides.sessionFederationIndex).toBe("function");
		expect(typeof provides.subjectSessionIndex).toBe("function");
		expect(typeof provides.subjectRevocation).toBe("function");
		expect(typeof provides.sessionLifecycleStore).toBe("function");
	});

	it("reads its own section, redis-session-stores, keyPrefix defaulting to ss:", () => {
		expect(redisSessionStoresModule).not.toHaveProperty("configSchema");
		expect(redisSessionStoresModule.section?.schema.parse(undefined)).toEqual({ keyPrefix: "ss:" });
	});
});

describe("redisSessionStoresModule wiring", () => {
	it("createApp wires all 6 components against per-purpose client slots", async () => {
		// Activator pattern (no `activate` field on ModuleSpec): use contributes.routes
		// to force closure root inclusion, then read from handle.components after boot.
		const activator = defineModule({
			name: "activator",
			requires: [
				"userSessionStore",
				"sessionRPRegistry",
				"sessionFamilyIndex",
				"sessionFederationIndex",
				"subjectSessionIndex",
				"subjectRevocation",
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

		const handle = await createApp({
			modules: [redisSessionStoresModule, activator],
			bootstrapComponents: {
				config: minBoot({ "redis-session-stores": { keyPrefix: "wire:" } }),
				pathResolver: (p: string) => p,
				// Spread every per-purpose wrapper; the module consumes its 6.
				...makeIoredisClients(raw),
			} as never,
		});

		try {
			const components = handle.components as Record<string, unknown>;
			expect((components.userSessionStore as { kind: string }).kind).toBe("redis");
			expect((components.sessionRPRegistry as { kind: string }).kind).toBe("redis");
			expect((components.sessionFamilyIndex as { kind: string }).kind).toBe("redis");
			expect((components.sessionFederationIndex as { kind: string }).kind).toBe("redis");
			expect((components.subjectSessionIndex as { kind: string }).kind).toBe("redis");
			expect((components.subjectRevocation as { kind: string }).kind).toBe("redis");
		} finally {
			await handle.dispose();
		}
	});

	it("provides a family index with the session-end capability, its mark under the section's keyPrefix (ss: by default)", async () => {
		const activator = defineModule({
			name: "activator",
			requires: ["sessionFamilyIndex"] as never,
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
				config: minBoot({}),
				pathResolver: (p: string) => p,
				...makeIoredisClients(raw),
			} as never,
		});
		try {
			const index = (handle.components as { sessionFamilyIndex?: SessionFamilyIndex })
				.sessionFamilyIndex;
			if (!supportsSessionEnd(index)) {
				throw new Error("the module's family index does not claim SupportsSessionEnd");
			}
			const expiresAt = new Date(Date.now() + 60_000);
			await index.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt);
			expect(await index.endSession("sid-1", expiresAt)).toEqual(["fam-A"]);
			expect(await raw.exists("ss:fi-ended:sid-1")).toBe(1);
			expect(await raw.zrange("ss:fi:sid-1", "0", "-1")).toEqual(["fam-A"]);
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

	const silentLogger = (): Logger & { warn: ReturnType<typeof vi.fn> } => {
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child: () => logger,
		};
		return logger as never;
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

	it("boots on a policy it cannot read, warning once on the logger slot", async () => {
		const logger = silentLogger();
		const handle = await createApp({
			modules: [redisSessionStoresModule, reader],
			bootstrapComponents: {
				config: minBoot({}),
				pathResolver: (p: string) => p,
				logger,
				...clientsReporting(async () => report(undefined, new Error("NOPERM"))),
			} as never,
		});
		try {
			const unchecked = logger.warn.mock.calls.filter(
				(call) => call[1] === "session_lifecycle_store_eviction_unchecked",
			);
			expect(unchecked).toHaveLength(1);
		} finally {
			await handle.dispose();
		}
	});
});
