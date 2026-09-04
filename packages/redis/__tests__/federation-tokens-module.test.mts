/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
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
		expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("allow-plaintext"));
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
