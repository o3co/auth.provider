/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { createChallengeStoreFactory, registerBuiltinChallengeStores } from "../factory.mjs";

describe("ChallengeStoreFactory", () => {
	it("createChallengeStoreFactory returns an empty factory", async () => {
		const factory = createChallengeStoreFactory();
		await expect(factory.create({ type: "memory" })).rejects.toThrow();
	});

	it("registerBuiltinChallengeStores registers the 'memory' builder", async () => {
		const factory = createChallengeStoreFactory();
		registerBuiltinChallengeStores(factory);
		const store = await factory.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});

	it("builds the 'memory' adapter with the cap its config gives, and the default without one", async () => {
		const factory = createChallengeStoreFactory();
		registerBuiltinChallengeStores(factory);
		const capped = (await factory.create({ type: "memory", maxEntries: 5 })) as {
			maxEntries: number;
		};
		expect(capped.maxEntries).toBe(5);
		const fromText = (await factory.create({ type: "memory", maxEntries: "7" })) as {
			maxEntries: number;
		};
		expect(fromText.maxEntries).toBe(7);
		const plain = (await factory.create({ type: "memory" })) as { maxEntries: number };
		expect(plain.maxEntries).toBe(1_000_000);
	});

	it("refuses a 'memory' adapter config whose cap it cannot use, naming the key", async () => {
		const factory = createChallengeStoreFactory();
		registerBuiltinChallengeStores(factory);
		await expect(factory.create({ type: "memory", maxEntries: 0 })).rejects.toThrow(
			new RangeError(
				"ChallengeStore memory adapter maxEntries must be a positive whole number (got 0)",
			),
		);
	});

	it("registering 'memory' twice throws AdapterFactoryError reason 'duplicate'", () => {
		const factory = createChallengeStoreFactory();
		registerBuiltinChallengeStores(factory);
		expect(() => registerBuiltinChallengeStores(factory)).toThrow(
			expect.objectContaining({ name: "AdapterFactoryError", reason: "duplicate" }),
		);
	});

	it("replace('memory', otherBuilder) overrides the builder; create returns the new value", async () => {
		const factory = createChallengeStoreFactory();
		registerBuiltinChallengeStores(factory);
		factory.replace("memory", () => ({
			kind: "memory-overridden",
			issue: async () => undefined,
			find: async () => null,
			consume: async () => false,
		}));
		const store = await factory.create({ type: "memory" });
		expect(store.kind).toBe("memory-overridden");
	});
});
