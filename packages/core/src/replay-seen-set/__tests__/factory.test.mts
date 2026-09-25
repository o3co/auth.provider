/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { createReplaySeenSetFactory, registerBuiltinReplaySeenSets } from "../factory.mjs";

describe("ReplaySeenSetFactory", () => {
	it("createReplaySeenSetFactory returns an empty factory", async () => {
		const factory = createReplaySeenSetFactory();
		await expect(factory.create({ type: "memory" })).rejects.toThrow();
	});

	it("registerBuiltinReplaySeenSets registers the 'memory' builder", async () => {
		const factory = createReplaySeenSetFactory();
		registerBuiltinReplaySeenSets(factory);
		const set = await factory.create({ type: "memory" });
		expect(set.kind).toBe("memory");
	});

	it("builds the 'memory' adapter with the cap its config gives, and the default without one", async () => {
		const factory = createReplaySeenSetFactory();
		registerBuiltinReplaySeenSets(factory);
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

	it("refuses a 'memory' adapter config whose cap is an explicit null", async () => {
		const factory = createReplaySeenSetFactory();
		registerBuiltinReplaySeenSets(factory);
		await expect(factory.create({ type: "memory", maxEntries: null })).rejects.toThrow(
			new RangeError(
				"ReplaySeenSet memory adapter maxEntries must be a positive whole number (got null)",
			),
		);
	});

	it("refuses a 'memory' adapter config whose cap it cannot use, naming the key", async () => {
		const factory = createReplaySeenSetFactory();
		registerBuiltinReplaySeenSets(factory);
		await expect(factory.create({ type: "memory", maxEntries: 0 })).rejects.toThrow(
			new RangeError(
				"ReplaySeenSet memory adapter maxEntries must be a positive whole number (got 0)",
			),
		);
	});

	it("registering 'memory' twice throws AdapterFactoryError reason 'duplicate'", () => {
		const factory = createReplaySeenSetFactory();
		registerBuiltinReplaySeenSets(factory);
		expect(() => registerBuiltinReplaySeenSets(factory)).toThrow(
			expect.objectContaining({ name: "AdapterFactoryError", reason: "duplicate" }),
		);
	});
});
