/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * `redisDeviceCodeStoreModule` through the boot planner (#433).
 *
 * The whole point of the module is that a composition running the device
 * grant can declare `deployment.mode = "multi"`. Before it existed, the only
 * store was the in-memory one, which `checkReplicaSafety` refuses under that
 * mode — correctly, since pending authorizations fork per replica — so the
 * grant was single-replica by construction. These tests prove the planner
 * accepts the Redis store where it refuses the memory one, and that the slot
 * it fills is the one `DEVICE_CODE_STORE_ABSENCE_POLICY` guards.
 */

import {
	createApp,
	DEVICE_CODE_STORE_ABSENCE_POLICY,
	defineModule,
	memoryDeviceCodeStoreModule,
	REPLICA_UNSAFE_MODULES,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redisDeviceCodeStoreModule } from "#/device-code-store.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";

let container: StartedTestContainer;
let raw: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 90_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

/**
 * Stands in for `deviceGrantModule`, which this package does not depend on:
 * reads the slot under the same absence policy the grant attaches, so a boot
 * here fails for the same reasons a real composition's would. The route
 * contribution is what puts it in the closure root.
 */
const deviceGrantStandIn = defineModule({
	name: "test:device-grant-stand-in",
	optional: ["deviceCodeStore"] as const,
	absencePolicies: { deviceCodeStore: DEVICE_CODE_STORE_ABSENCE_POLICY },
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
		deployment: { mode: "multi" },
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
	it('boots under deployment.mode = "multi" and fills deviceCodeStore with the Redis adapter', async () => {
		const handle = await createApp({
			modules: [redisDeviceCodeStoreModule, deviceGrantStandIn],
			bootstrapComponents: {
				config: multiReplicaConfig({ redisDeviceCodeStore: { keyPrefix: "wire:" } }),
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

	it("fills the slot DEVICE_CODE_STORE_ABSENCE_POLICY guards — without it, boot demands a declaration", async () => {
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
			reason: "component-absence-undeclared",
			details: { componentKey: "deviceCodeStore" },
		});
	});

	it("throws BootError {missing-required-component} when the client slot is absent", async () => {
		// The failure #439 paid for in the standalone: a Redis-branch module
		// whose client slot nothing provides. Named at boot, not at first poll.
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
