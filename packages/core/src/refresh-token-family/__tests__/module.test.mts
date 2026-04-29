/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import {
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenRotationModule,
	memoryRefreshTokenFamilyStoreModule,
} from "../module.mjs";

describe("memoryRefreshTokenFamilyStoreModule", () => {
	it("has the canonical module name 'core-refresh-token-family-store-memory'", () => {
		expect(memoryRefreshTokenFamilyStoreModule.name).toBe("core-refresh-token-family-store-memory");
	});

	it("provides refreshTokenFamilyStore via factory; no requires", () => {
		expect(memoryRefreshTokenFamilyStoreModule.requires ?? []).toEqual([]);
		expect(typeof memoryRefreshTokenFamilyStoreModule.provides?.refreshTokenFamilyStore).toBe(
			"function",
		);
		const store = memoryRefreshTokenFamilyStoreModule.provides?.refreshTokenFamilyStore?.(
			{} as never,
		);
		expect(store).toBeDefined();
	});
});

describe("defaultRefreshTokenRotationModule", () => {
	it("has the canonical module name 'core-default-refresh-token-rotation'", () => {
		expect(defaultRefreshTokenRotationModule.name).toBe("core-default-refresh-token-rotation");
	});

	it("requires refreshTokenFamilyStore and provides refreshTokenRotation", () => {
		expect(new Set(defaultRefreshTokenRotationModule.requires ?? [])).toEqual(
			new Set(["refreshTokenFamilyStore"]),
		);
		expect(typeof defaultRefreshTokenRotationModule.provides?.refreshTokenRotation).toBe(
			"function",
		);
	});
});

describe("defaultRefreshTokenFamilyRevocationModule", () => {
	it("has the canonical module name 'core-default-refresh-token-family-revocation'", () => {
		expect(defaultRefreshTokenFamilyRevocationModule.name).toBe(
			"core-default-refresh-token-family-revocation",
		);
	});

	it("requires refreshTokenFamilyStore and provides refreshTokenFamilyRevocation", () => {
		expect(new Set(defaultRefreshTokenFamilyRevocationModule.requires ?? [])).toEqual(
			new Set(["refreshTokenFamilyStore"]),
		);
		expect(
			typeof defaultRefreshTokenFamilyRevocationModule.provides?.refreshTokenFamilyRevocation,
		).toBe("function");
	});
});
