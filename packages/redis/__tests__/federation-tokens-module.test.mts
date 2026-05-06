/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import {
	redisFederationTokenStoreBuilder,
	redisFederationTokenStoreModule,
} from "../src/federation-tokens.mjs";

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
