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

	it("registering 'memory' twice throws AdapterFactoryError reason 'duplicate'", () => {
		const factory = createReplaySeenSetFactory();
		registerBuiltinReplaySeenSets(factory);
		expect(() => registerBuiltinReplaySeenSets(factory)).toThrow(
			expect.objectContaining({ name: "AdapterFactoryError", reason: "duplicate" }),
		);
	});
});
