/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import {
	createRefreshTokenFamilyStoreFactory,
	registerBuiltinRefreshTokenFamilyStores,
} from "../factory.mjs";

describe("createRefreshTokenFamilyStoreFactory", () => {
	it("returns a factory whose kind label is 'RefreshTokenFamilyStore' (PascalCase convention)", async () => {
		const f = createRefreshTokenFamilyStoreFactory();
		// kind label surfaces in error messages; verify via thrown error
		await expect(f.create({ type: "nonexistent" })).rejects.toThrow("[RefreshTokenFamilyStore]");
	});

	it("starts empty (no builders registered)", async () => {
		const f = createRefreshTokenFamilyStoreFactory();
		await expect(f.create({ type: "memory" })).rejects.toThrow();
	});

	it("register('memory', ...) followed by create('memory') returns a memory store", async () => {
		const f = createRefreshTokenFamilyStoreFactory();
		registerBuiltinRefreshTokenFamilyStores(f);
		const store = await f.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});

	it("register('memory', ...) twice throws (A6+A7 duplicate policy)", () => {
		const f = createRefreshTokenFamilyStoreFactory();
		registerBuiltinRefreshTokenFamilyStores(f);
		expect(() => registerBuiltinRefreshTokenFamilyStores(f)).toThrow(
			expect.objectContaining({ name: "AdapterFactoryError", reason: "duplicate" }),
		);
	});
});

describe("registerBuiltinRefreshTokenFamilyStores", () => {
	it("registers 'memory' as a builtin", async () => {
		const f = createRefreshTokenFamilyStoreFactory();
		registerBuiltinRefreshTokenFamilyStores(f);
		const store = await f.create({ type: "memory" });
		expect(store).toBeDefined();
	});
});
