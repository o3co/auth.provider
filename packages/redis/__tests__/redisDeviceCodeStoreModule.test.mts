/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * `redisDeviceCodeStoreModule` through the boot planner. With it, a
 * composition running the device grant can declare `core.deployment.mode =
 * "multi"`: `checkReplicaSafety` refuses the in-memory store under that mode,
 * since pending authorizations fork per replica. Pinned: the planner accepts
 * the Redis store where it refuses the memory one, and the slot it fills is
 * the one an enabled device grant cannot run without.
 */

import {
	createApp,
	defineModule,
	memoryDeviceCodeStoreModule,
	REPLICA_UNSAFE_MODULES,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redisDeviceCodeStoreModule } from "#/device-code-store.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { testRedis } from "./support/redis.mjs";

let raw: Redis;

beforeAll(async () => {
	const at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	raw?.disconnect();
});

/**
 * Stands in for an enabled `deviceAuthorizationGrantModule`, which this
 * package does not depend on: the grant cannot run without a store, so the
 * stand-in requires the slot, and a boot here fails without one as a
 * composition with the grant enabled does. The route contribution is what
 * puts it in the closure root.
 */
const deviceGrantStandIn = defineModule({
	name: "test:device-grant-stand-in",
	requires: ["deviceCodeStore"] as const,
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

const multiReplicaConfig = (extra: Record<string, unknown> = {}) =>
	({
		...makeValidCoreConfig(),
		core: { deployment: { mode: "multi" } },
		...extra,
	}) as never;

describe("redisDeviceCodeStoreModule manifest", () => {
	// Name, requires and configSchema are pinned with the other modules in
	// `modules.test.mts`; here is what matters for replica safety.
	it("provides deviceCodeStore", () => {
		expect(typeof redisDeviceCodeStoreModule.provides?.deviceCodeStore).toBe("function");
	});

	it("is not a module the replica-safety guard refuses, where the memory one is", () => {
		// The guard is keyed by module name, so the name is what has to stay
		// off the list.
		expect(REPLICA_UNSAFE_MODULES).not.toContain(redisDeviceCodeStoreModule.name);
		expect(REPLICA_UNSAFE_MODULES).toContain(memoryDeviceCodeStoreModule.name);
	});
});

describe("redisDeviceCodeStoreModule wiring", () => {
	it('boots under core.deployment.mode = "multi" and fills deviceCodeStore with the Redis adapter', async () => {
		const handle = await createApp({
			modules: [redisDeviceCodeStoreModule, deviceGrantStandIn],
			bootstrapComponents: {
				config: multiReplicaConfig({ "redis-device-code-store": { keyPrefix: "wire:" } }),
				pathResolver: (p: string) => p,
				...makeIoredisClients(raw),
			} as never,
		});
		try {
			const store = (handle.components as Record<string, unknown>).deviceCodeStore as {
				kind: string;
				create(input: unknown): Promise<void>;
			};
			expect(store.kind).toBe("redis");

			// The configured prefix reached the adapter, not a default: the
			// record lands under `wire:`.
			await store.create({
				deviceCode: "dc-wired",
				userCode: "BCDFGHJK",
				clientId: "tv",
				expiresAtMs: Date.now() + 60_000,
				intervalSeconds: 5,
				requestedScope: undefined,
			});
			expect((await raw.keys("wire:*")).length).toBe(2);
		} finally {
			await handle.dispose();
		}
	});

	it('is what the memory store cannot be: the same composition on memoryDeviceCodeStoreModule is refused under "multi"', async () => {
		// Proves the guard is live on this boot path, so the case above passing
		// means something — and names the module it refuses.
		await expect(
			createApp({
				modules: [memoryDeviceCodeStoreModule, deviceGrantStandIn],
				bootstrapComponents: {
					config: multiReplicaConfig(),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "replica-unsafe-adapter",
			details: { modules: [memoryDeviceCodeStoreModule.name] },
		});
	});

	it("fills the slot the device grant requires — without it, boot names deviceCodeStore as missing", async () => {
		await expect(
			createApp({
				modules: [deviceGrantStandIn],
				bootstrapComponents: {
					config: multiReplicaConfig(),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "missing-required-component",
			details: { missingKey: "deviceCodeStore" },
		});
	});

	it("throws BootError {missing-required-component} when the client slot is absent", async () => {
		// A Redis-branch module whose client slot nothing provides is named at
		// boot, not at first poll.
		await expect(
			createApp({
				modules: [redisDeviceCodeStoreModule, deviceGrantStandIn],
				bootstrapComponents: {
					config: multiReplicaConfig(),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toMatchObject({ name: "BootError", reason: "missing-required-component" });
	});
});
