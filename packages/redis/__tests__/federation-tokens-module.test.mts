/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { createApp, defineModule } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FederationTokenStoreClient } from "../src/clients.mjs";
import {
	createRedisFederationTokenStore,
	redisFederationTokenStoreBuilder,
	redisFederationTokenStoreModule,
	redisFederationTokenStoreModuleFor,
} from "../src/federation-tokens.mjs";

const fakeClient = () => ({
	get: () => null,
	set: () => null,
	del: () => 0,
	unlink: () => 0,
	sAddWithTtl: async () => {},
	sRem: async () => 0,
	sScanIterator: () => [],
	scanIterator: () => [],
	compareAndDelete: async () => false,
});

/** Runs a module's `federationTokenStore` provider against a plaintext config. */
const provideFrom = (
	module: { provides?: { federationTokenStore?: unknown } },
	deployment?: { mode?: string },
) => {
	const provider = module.provides?.federationTokenStore as (deps: unknown) => unknown;
	return provider({
		federationTokenStoreClient: fakeClient(),
		config: {
			redisFederationTokenStore: {
				keyPrefix: "ft:",
				ttl: 86400,
				encryptionMode: "allow-plaintext",
				scanFallback: true,
			},
			...(deployment ? { deployment } : {}),
		},
	});
};

describe("#473 — the module hands the guard the selected environment and deployment.mode", () => {
	let origEnv: string | undefined;
	let warnSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		origEnv = process.env.NODE_ENV;
		process.env.NODE_ENV = "development";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
	});

	afterEach(() => {
		if (origEnv === undefined) delete process.env.NODE_ENV;
		else process.env.NODE_ENV = origEnv;
		warnSpy.mockRestore();
	});

	it("keeps the manifest of the default module: same name, requires and configSchema", () => {
		const m = redisFederationTokenStoreModuleFor({ environment: "production" });
		expect(m.name).toBe(redisFederationTokenStoreModule.name);
		expect(m.requires).toEqual(redisFederationTokenStoreModule.requires);
		expect(m.configSchema).toBe(redisFederationTokenStoreModule.configSchema);
	});

	it("refuses plaintext when the composition root passes a production environment", () => {
		expect(() =>
			provideFrom(redisFederationTokenStoreModuleFor({ environment: "production" })),
		).toThrow(/the environment is "production"/);
	});

	it('refuses plaintext under deployment.mode = "multi" read from config — default module included', () => {
		expect(() => provideFrom(redisFederationTokenStoreModule, { mode: "multi" })).toThrow(
			/deployment\.mode is "multi"/,
		);
		expect(() =>
			provideFrom(redisFederationTokenStoreModuleFor({ environment: "development" }), {
				mode: "multi",
			}),
		).toThrow(/deployment\.mode is "multi"/);
	});

	it("warns and builds the store in development with deployment.mode unset or single", () => {
		const store = provideFrom(redisFederationTokenStoreModuleFor({ environment: "development" }), {
			mode: "single",
		}) as { kind: string };
		expect(store.kind).toBe("redis");
		expect((provideFrom(redisFederationTokenStoreModuleFor({})) as { kind: string }).kind).toBe(
			"redis",
		);
		expect(warnSpy).toHaveBeenCalledWith(
			{ store: "federation-tokens", mode: "allow-plaintext" },
			"federation_store_plaintext",
		);
	});
});

describe("redisFederationTokenStoreModule", () => {
	it("has the canonical name", () => {
		expect(redisFederationTokenStoreModule.name).toBe("redis-federation-token-store");
	});

	it("requires federationTokenStoreClient and config", () => {
		expect(redisFederationTokenStoreModule.requires).toEqual([
			"federationTokenStoreClient",
			"config",
		]);
	});

	it("provides federationTokenStore", () => {
		expect(typeof redisFederationTokenStoreModule.provides?.federationTokenStore).toBe("function");
	});

	it("declares a configSchema with redisFederationTokenStore namespaced key", () => {
		const schema = redisFederationTokenStoreModule.configSchema;
		expect(schema).toBeDefined();
		// Default values flow through when only the namespace key is provided
		const parsed = schema?.safeParse({ redisFederationTokenStore: {} });
		expect(parsed?.success).toBe(true);
		if (parsed?.success) {
			expect(parsed.data.redisFederationTokenStore.keyPrefix).toBe("ft:");
			expect(parsed.data.redisFederationTokenStore.ttl).toBe(86400);
			expect(parsed.data.redisFederationTokenStore.encryptionMode).toBe("required");
		}
	});
});

describe("redisFederationTokenStoreBuilder", () => {
	it("rejects missing client", () => {
		expect(() => redisFederationTokenStoreBuilder({})).toThrow(/'client' option is required/);
	});

	it("rejects encryption.required without 32-byte key", () => {
		const fakeClient = {
			get: () => null,
			set: () => null,
			del: () => 0,
			unlink: () => 0,
			sAddWithTtl: async () => {},
			sRem: async () => 0,
			sScanIterator: () => [],
			scanIterator: () => [],
			compareAndDelete: async () => false,
		};
		expect(() =>
			redisFederationTokenStoreBuilder({
				client: fakeClient,
				encryption: { mode: "required", key: Buffer.alloc(16) },
			}),
		).toThrow(/32 bytes/);
	});

	it("accepts encryption.allow-plaintext", () => {
		const fakeClient = {
			get: () => null,
			set: () => null,
			del: () => 0,
			unlink: () => 0,
			sAddWithTtl: async () => {},
			sRem: async () => 0,
			sScanIterator: () => [],
			scanIterator: () => [],
			compareAndDelete: async () => false,
		};
		// No throw expected
		const store = redisFederationTokenStoreBuilder({
			client: fakeClient,
			encryption: { mode: "allow-plaintext" },
		});
		expect(store.kind).toBe("redis");
	});
});

/**
 * Stands in for the routes that read the store, so that the store is in the
 * closure boot builds.
 */
const tokensReader = defineModule({
	name: "test:federation-token-store-reader",
	optional: ["federationTokenStore"] as const,
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

/**
 * Boots the module through `createApp` over a valid core configuration,
 * requires the boot to fail on the store's provider, naming the module, and
 * answers the BootError's cause.
 */
const bootRefusal = async (extra: Record<string, unknown>): Promise<unknown> => {
	const boot = createApp({
		modules: [redisFederationTokenStoreModule, tokensReader],
		bootstrapComponents: {
			config: { ...makeValidCoreConfig(), ...extra },
			pathResolver: (p: string) => p,
			federationTokenStoreClient: fakeClient(),
		} as never,
	});
	await expect(boot).rejects.toMatchObject({
		name: "BootError",
		reason: "provides-factory-failed",
		details: { module: "redis-federation-token-store", componentKey: "federationTokenStore" },
	});
	return ((await boot.catch((err: unknown) => err)) as Error).cause;
};

const PLAINTEXT_UNDER_MULTI =
	'[federation-tokens] mode "allow-plaintext" is refused because deployment.mode is "multi" ' +
	"(a multi-replica deployment is never a development box). " +
	'Set mode to "required" and provide a 32-byte encryption key, OR set ' +
	"FEDERATION_TOKENS_ALLOW_INSECURE=1 to override (NOT recommended for production).";

const KEY_OF_16 = Buffer.alloc(16, 7).toString("base64");

describe("every setting the token store is given and cannot use is refused as a RangeError", () => {
	let insecure: string | undefined;

	beforeEach(() => {
		insecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
	});

	afterEach(() => {
		if (insecure !== undefined) process.env.FEDERATION_TOKENS_ALLOW_INSECURE = insecure;
	});

	it("through the factory: a key that is not 32 bytes, plaintext where it is refused, a TTL past the Date range", () => {
		const client = fakeClient() as unknown as FederationTokenStoreClient;
		expect(() =>
			createRedisFederationTokenStore({
				client,
				encryption: { mode: "required", key: Buffer.alloc(16, 7) },
			}),
		).toThrow(new RangeError("FederationTokenStore redis: encryption key must be 32 bytes"));
		expect(() =>
			createRedisFederationTokenStore({
				client,
				encryption: { mode: "allow-plaintext" },
				deploymentMode: "multi",
			}),
		).toThrow(new RangeError(PLAINTEXT_UNDER_MULTI));
		expect(() =>
			createRedisFederationTokenStore({
				client,
				encryption: { mode: "required", key: Buffer.alloc(32, 7) },
				ttl: 1e20,
			}),
		).toThrow(RangeError);
	});

	it("through the builder: a configured key that does not decode to 32 bytes, or none", () => {
		const message =
			"federationTokenStore.redis: encryption.key must decode to 32 bytes (AES-256) when encryption.mode is 'required' (the default)";
		for (const key of [KEY_OF_16, Buffer.alloc(16, 7), undefined]) {
			expect(
				() =>
					redisFederationTokenStoreBuilder({
						client: fakeClient(),
						encryption: { mode: "required", key },
					}),
				String(key),
			).toThrow(new RangeError(message));
		}
	});

	it.each([
		[
			"a key that does not decode to 32 bytes",
			{ redisFederationTokenStore: { encryptionKey: KEY_OF_16 } },
			"federationTokenStore.redis: encryption.key must decode to 32 bytes (AES-256) when encryption.mode is 'required' (the default)",
		],
		[
			"no key under the default mode",
			{ redisFederationTokenStore: {} },
			"federationTokenStore.redis: encryption.key must decode to 32 bytes (AES-256) when encryption.mode is 'required' (the default)",
		],
		[
			'plaintext under deployment.mode = "multi"',
			{
				redisFederationTokenStore: { encryptionMode: "allow-plaintext" },
				deployment: { mode: "multi" },
			},
			PLAINTEXT_UNDER_MULTI,
		],
	])("at boot: %s is the BootError's cause, as a RangeError", async (_what, extra, message) => {
		const cause = await bootRefusal(extra);
		expect(cause).toStrictEqual(new RangeError(message));
		expect(cause).toBeInstanceOf(RangeError);
	});

	it("leaves a missing client an Error: a composition fault, refused as every Redis builder refuses it", () => {
		// Not a setting that is given and unusable, but a dependency that was not
		// given; the module path never reaches it (`requires` refuses first).
		let thrown: unknown;
		try {
			redisFederationTokenStoreBuilder({});
		} catch (err) {
			thrown = err;
		}
		expect((thrown as Error).constructor).toBe(Error);
		expect((thrown as Error).message).toBe(
			"federationTokenStore.redis: 'client' option is required",
		);
	});
});
