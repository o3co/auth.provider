/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import {
	createFederationTokenStoreFactory,
	registerBuiltinFederationTokenStores,
} from "../factory.mjs";

describe("FederationTokenStoreFactory", () => {
	it("built-in memory is registered", async () => {
		const f = createFederationTokenStoreFactory();
		registerBuiltinFederationTokenStores(f);
		const store = await f.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});

	it("redis defaults encryption.mode to 'required' when omitted; missing key throws", async () => {
		const f = createFederationTokenStoreFactory();
		registerBuiltinFederationTokenStores(f);
		await expect(
			f.create({
				type: "redis",
				client: {
					get: async () => null,
					set: async () => "OK",
					del: async () => 0,
					scanIterator: async function* () {},
				},
				// encryption omitted — should default to mode: "required".
			}),
		).rejects.toThrow(/32 bytes/);
	});

	it("redis rejects an incompatible client (missing scanIterator)", async () => {
		const f = createFederationTokenStoreFactory();
		registerBuiltinFederationTokenStores(f);
		await expect(
			f.create({
				type: "redis",
				client: {
					get: async () => null,
					set: async () => "OK",
					del: async () => 0,
					// scanIterator missing
				},
				encryption: { mode: "allow-plaintext" },
			}),
		).rejects.toThrow(/scanIterator/);
	});

	it("redis rejects a client missing multiple methods with a combined message", async () => {
		const f = createFederationTokenStoreFactory();
		registerBuiltinFederationTokenStores(f);
		await expect(
			f.create({
				type: "redis",
				client: { get: async () => null }, // missing set, del, scanIterator
				encryption: { mode: "allow-plaintext" },
			}),
		).rejects.toThrow(/set.*del.*scanIterator/);
	});

	it("redis with mode=required needs a 32-byte key", async () => {
		const f = createFederationTokenStoreFactory();
		registerBuiltinFederationTokenStores(f);
		await expect(
			f.create({
				type: "redis",
				client: {
					get: async () => null,
					set: async () => "OK",
					del: async () => 0,
					scanIterator: async function* () {},
				},
				encryption: { mode: "required", key: Buffer.alloc(16) },
			}),
		).rejects.toThrow(/32 bytes/);
	});

	it("redis with mode=allow-plaintext logs warning but succeeds", async () => {
		const warnings: string[] = [];
		const originalWarn = console.warn;
		console.warn = (msg: string) => warnings.push(msg);
		try {
			const f = createFederationTokenStoreFactory();
			registerBuiltinFederationTokenStores(f);
			const store = await f.create({
				type: "redis",
				client: {
					get: async () => null,
					set: async () => "OK",
					del: async () => 0,
					scanIterator: async function* () {},
				},
				encryption: { mode: "allow-plaintext" },
			});
			expect(store.kind).toBe("redis");
			expect(warnings.some((w) => /plaintext/i.test(w))).toBe(true);
		} finally {
			console.warn = originalWarn;
		}
	});
});
