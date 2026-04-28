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
