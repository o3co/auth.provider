/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { createMemoryRefreshTokenFamilyStore } from "../adapters/memory.mjs";
import { createRefreshTokenFamilyRevocation } from "../revocation.mjs";
import type {
	RefreshTokenFamily,
	RefreshTokenFamilyStore,
	RefreshTokenFamilyUpdateResult,
} from "../types.mjs";

const FUTURE = (): number => Date.now() + 60_000;

const seed = async () => {
	const store = createMemoryRefreshTokenFamilyStore();
	const revocation = createRefreshTokenFamilyRevocation({
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

describe("createRefreshTokenFamilyRevocation", () => {
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

	it("revokeFamily updater returns a frozen value (I3 freeze regression)", async () => {
		// Mirrors the rotation.mts updater-freeze pattern. Adapters also freeze
		// on persist, so this test pins the wrapper-layer freeze (defence-in-
		// depth) directly: a future refactor stripping the freeze in
		// revocation.mts must fail this assertion. Without it, the symmetry
		// with rotation.mts could silently drift on edits.
		// We intercept the updater via a recording stub for the underlying store.
		let captured: RefreshTokenFamily | null = null;
		const initial: RefreshTokenFamily = Object.freeze({
			familyId: "fam-1",
			activeJti: "jti-1",
			revoked: false,
			expiresAtMs: FUTURE(),
		});
		const stubStore: RefreshTokenFamilyStore = {
			kind: "stub",
			async registerFamily() {},
			async findFamily() {
				return initial;
			},
			async updateFamily(_id, updater): Promise<RefreshTokenFamilyUpdateResult> {
				const next = updater(initial);
				if (next === null) return { outcome: "aborted" };
				captured = next;
				return { outcome: "committed", family: Object.freeze({ ...next }) };
			},
		};
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: stubStore,
		});
		await revocation.revokeFamily("fam-1");
		expect(captured).not.toBeNull();
		expect(Object.isFrozen(captured)).toBe(true);
	});
});
