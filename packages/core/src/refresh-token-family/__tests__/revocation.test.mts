/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { createMemoryRefreshTokenFamilyStore } from "../adapters/memory.mjs";
import { createDefaultRefreshTokenFamilyRevocation } from "../revocation.mjs";

const FUTURE = (): number => Date.now() + 60_000;

const seed = async () => {
	const store = createMemoryRefreshTokenFamilyStore();
	const revocation = createDefaultRefreshTokenFamilyRevocation({
		refreshTokenFamilyStore: store,
	});
	await store.registerFamily({
		familyId: "fam-1",
		activeJti: "jti-1",
		revoked: false,
		expiresAtMs: FUTURE(),
	});
	return { store, revocation };
};

describe("createDefaultRefreshTokenFamilyRevocation", () => {
	it("revokeFamily flips revoked to true", async () => {
		const { store, revocation } = await seed();
		await revocation.revokeFamily("fam-1");
		const after = await store.findFamily("fam-1");
		expect(after?.revoked).toBe(true);
	});

	it("revokeFamily is idempotent (second call no-ops)", async () => {
		const { revocation } = await seed();
		await revocation.revokeFamily("fam-1");
		await expect(revocation.revokeFamily("fam-1")).resolves.toBeUndefined();
	});

	it("revokeFamily for non-existent family is a no-op success", async () => {
		const { revocation } = await seed();
		await expect(revocation.revokeFamily("ghost-id")).resolves.toBeUndefined();
	});

	it("isFamilyRevoked returns false initially", async () => {
		const { revocation } = await seed();
		expect(await revocation.isFamilyRevoked("fam-1")).toBe(false);
	});

	it("isFamilyRevoked returns true after revokeFamily", async () => {
		const { revocation } = await seed();
		await revocation.revokeFamily("fam-1");
		expect(await revocation.isFamilyRevoked("fam-1")).toBe(true);
	});

	it("isFamilyRevoked returns false for non-existent family", async () => {
		const { revocation } = await seed();
		expect(await revocation.isFamilyRevoked("ghost-id")).toBe(false);
	});
});
