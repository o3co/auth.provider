/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * `redisConsentStoreModule` through the boot planner (#561).
 *
 * The module exists so a composition serving clients that are not
 * first-party can declare `deployment.mode = "multi"`. Before it, the only
 * provider of the two consent slots was `memoryConsentStoreModule`, which
 * `checkReplicaSafety` refuses under that mode by name — correctly, since
 * consent and parked requests fork per replica. These tests prove the planner
 * accepts the Redis module where it refuses the memory one, that the module
 * fills both slots the consent step needs, and that the configured namespace
 * reaches both adapters.
 */

import {
	createApp,
	defineModule,
	memoryConsentStoreModule,
	REPLICA_UNSAFE_MODULES,
	replicaUnsafeReason,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redisConsentStoreModule } from "#/consent-store.mjs";
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
 * Stands in for the OAuth module, which this package does not depend on:
 * reads both consent slots as `oauthModule` does (optional), and contributes a
 * route so it is in the closure root.
 */
const consentStepStandIn = defineModule({
	name: "test:consent-step-stand-in",
	optional: ["consentStore", "pendingConsentStore"] as const,
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

describe("redisConsentStoreModule manifest", () => {
	it("provides both slots the consent step needs, as the memory module does", () => {
		expect(Object.keys(redisConsentStoreModule.provides ?? {}).sort()).toEqual(
			Object.keys(memoryConsentStoreModule.provides ?? {}).sort(),
		);
		expect(Object.keys(redisConsentStoreModule.provides ?? {}).sort()).toEqual([
			"consentStore",
			"pendingConsentStore",
		]);
	});

	it("declares nothing the replica-safety guard refuses, where the memory module does", () => {
		expect(replicaUnsafeReason(redisConsentStoreModule)).toBeUndefined();
		expect(REPLICA_UNSAFE_MODULES).not.toContain(redisConsentStoreModule.name);
		expect(REPLICA_UNSAFE_MODULES).toContain(memoryConsentStoreModule.name);
	});
});

describe("redisConsentStoreModule wiring", () => {
	it('boots under deployment.mode = "multi" and fills both slots with the Redis adapters', async () => {
		const handle = await createApp({
			modules: [redisConsentStoreModule, consentStepStandIn],
			bootstrapComponents: {
				config: multiReplicaConfig({ redisConsentStore: { keyPrefix: "wire:" } }),
				pathResolver: (p: string) => p,
				...makeIoredisClients(raw),
			} as never,
		});
		try {
			const components = handle.components as Record<string, unknown>;
			const consentStore = components.consentStore as {
				kind: string;
				grant(record: unknown): Promise<void>;
			};
			const pendingConsentStore = components.pendingConsentStore as {
				kind: string;
				set(record: unknown): Promise<void>;
			};
			expect(consentStore.kind).toBe("redis");
			expect(pendingConsentStore.kind).toBe("redis");

			// The configured prefix reached both adapters, not a default.
			await consentStore.grant({
				sub: "u",
				clientId: "c",
				scopes: ["read"],
				grantedAt: 1,
				expiresAt: undefined,
			});
			await pendingConsentStore.set({
				challenge: "ch",
				sessionId: "sess",
				sub: "u",
				clientId: "c",
				scopes: ["read"],
				grantedScopes: [],
				authorizeUrl: "https://issuer.example/oauth/authorize",
				redirectUri: "https://c.example/cb",
				createdAt: Date.now(),
				expiresAt: Date.now() + 60_000,
				state: undefined,
			});
			expect((await raw.keys("wire:*")).sort()).toEqual([
				"wire:rec:1:u|1:c",
				"wire:{pending}:ch:ch",
				"wire:{pending}:sess:sess",
			]);
		} finally {
			await handle.dispose();
		}
	});

	it('is what the memory module cannot be: the same composition on memoryConsentStoreModule is refused under "multi"', async () => {
		// Proves the guard is live on this boot path, so the case above passing
		// means something — and names the module it refuses.
		await expect(
			createApp({
				modules: [memoryConsentStoreModule, consentStepStandIn],
				bootstrapComponents: {
					config: multiReplicaConfig(),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "replica-unsafe-adapter",
			details: { modules: [memoryConsentStoreModule.name] },
		});
	});

	it("throws BootError {missing-required-component} when a client slot is absent", async () => {
		const { consentStoreClient } = makeIoredisClients(raw);
		await expect(
			createApp({
				modules: [redisConsentStoreModule, consentStepStandIn],
				bootstrapComponents: {
					config: multiReplicaConfig(),
					pathResolver: (p: string) => p,
					consentStoreClient,
				} as never,
			}),
		).rejects.toMatchObject({ name: "BootError", reason: "missing-required-component" });
	});
});
