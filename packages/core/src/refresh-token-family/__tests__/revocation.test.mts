/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { REVOCATION_RETENTION_ALLOWANCE_MS } from "#/jwt/verify.mjs";
import { createMemoryRefreshTokenFamilyStore } from "#/refresh-token-family/adapters/memory.mjs";
import { RefreshTokenStorageError } from "#/refresh-token-family/errors.mjs";
import { withReason } from "#/refresh-token-family/reason.mjs";
import {
	createRefreshTokenFamilyRevocation,
	REVOKED_WITHOUT_RECORD_JTI,
} from "#/refresh-token-family/revocation.mjs";
import type {
	RefreshTokenFamily,
	RefreshTokenFamilyStore,
	RefreshTokenFamilyUpdateResult,
} from "#/refresh-token-family/types.mjs";

const FUTURE = (): number => Date.now() + 60_000;

const seed = async () => {
	const store = createMemoryRefreshTokenFamilyStore();
	const revocation = createRefreshTokenFamilyRevocation({
		refreshTokenFamilyStore: store,
		accessTokenHorizonMs: 3_600_000,
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

	it("revokeFamily for a family with no record succeeds, and records it as revoked", async () => {
		// The record may have run out while an access token it minted is still
		// live; the revocation has to reach that token (`retention.mts`).
		const { revocation } = await seed();
		await expect(revocation.revokeFamily("ghost-id")).resolves.toBeUndefined();
		expect(await revocation.isFamilyRevoked("ghost-id")).toBe(true);
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
				const decision = updater(initial);
				if (decision.action === "abort") {
					return { outcome: "aborted", ...withReason(decision.reason) };
				}
				captured = decision.family;
				return {
					outcome: "committed",
					family: Object.freeze({ ...decision.family }),
					...withReason(decision.reason),
				};
			},
		};
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: stubStore,
			accessTokenHorizonMs: 3_600_000,
		});
		await revocation.revokeFamily("fam-1");
		expect(captured).not.toBeNull();
		expect(Object.isFrozen(captured)).toBe(true);
	});
});

/**
 * `revokeFamily` for a family with no record registers a revoked one. Between
 * the "not found" and the registration, a concurrent revocation (or
 * registration) can write the same record: `registerFamily` then refuses with
 * `duplicate-family`, and the wrapper takes a second pass, which finds the
 * record and revokes it — or finds it already revoked. Any other refusal is
 * the store's, and propagates. A second collision means the revocation is not
 * known to be recorded: `conflict-exhausted`, which a caller answers as an
 * outage and never as a revocation done.
 *
 * A scripted store plays each pass exactly; the clock is fixed so the
 * retention rule's expiry can be checked to the millisecond.
 */
describe("createRefreshTokenFamilyRevocation — a record that appears while a missing family is revoked", () => {
	const NOW = 1_800_000_000_000;
	const HORIZON_MS = 3_600_000;

	afterEach(() => {
		vi.useRealTimers();
	});

	type Pass = "not-found" | RefreshTokenFamily;

	/**
	 * A store whose `updateFamily` answers each pass from `passes` — "not
	 * found", or the record the updater is shown — and whose `registerFamily`
	 * throws each of `registerErrors` in turn. Every call is recorded.
	 */
	const scriptedStore = (passes: readonly Pass[], registerErrors: readonly unknown[]) => {
		const decisions: Array<{ action: string; family?: RefreshTokenFamily }> = [];
		const registered: RefreshTokenFamily[] = [];
		let pass = 0;
		let registration = 0;
		const store: RefreshTokenFamilyStore = {
			kind: "scripted",
			async registerFamily(family) {
				registered.push(family);
				const err = registerErrors[registration++];
				if (err !== undefined) throw err;
			},
			async findFamily() {
				return null;
			},
			async updateFamily(_id, updater): Promise<RefreshTokenFamilyUpdateResult> {
				const current = passes[pass++];
				if (current === undefined) throw new Error("scripted store: no pass left");
				if (current === "not-found") return { outcome: "not-found" };
				const decision = updater(current);
				decisions.push(decision);
				if (decision.action === "abort") {
					return { outcome: "aborted", ...withReason(decision.reason) };
				}
				return {
					outcome: "committed",
					family: decision.family,
					...withReason(decision.reason),
				};
			},
		};
		return {
			store,
			decisions,
			registered,
			updatePasses: () => pass,
			registrations: () => registration,
		};
	};

	const revocationOver = (store: RefreshTokenFamilyStore) => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(NOW);
		return createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: store,
			accessTokenHorizonMs: HORIZON_MS,
		});
	};

	const duplicate = () => new RefreshTokenStorageError({ reason: "duplicate-family" });

	it("revokes the record a concurrent write registered, keeping it by the retention rule", async () => {
		const appeared: RefreshTokenFamily = Object.freeze({
			familyId: "fam-race",
			activeJti: "jti-live",
			revoked: false,
			expiresAtMs: NOW + 60_000,
		});
		const scripted = scriptedStore(["not-found", appeared], [duplicate()]);

		await expect(revocationOver(scripted.store).revokeFamily("fam-race")).resolves.toBeUndefined();

		expect(scripted.updatePasses()).toBe(2);
		expect(scripted.registrations()).toBe(1);
		// The first pass tried to register a revoked record of its own.
		expect(scripted.registered[0]).toMatchObject({
			familyId: "fam-race",
			activeJti: REVOKED_WITHOUT_RECORD_JTI,
			revoked: true,
		});
		// The second committed the record it found, revoked, kept until the
		// later of its own expiry and now + the access-token horizon, plus the
		// retention allowance.
		expect(scripted.decisions).toHaveLength(1);
		expect(scripted.decisions[0]).toMatchObject({ action: "commit" });
		expect(scripted.decisions[0]?.family).toEqual({
			familyId: "fam-race",
			activeJti: "jti-live",
			revoked: true,
			expiresAtMs: Math.ceil(
				Math.max(appeared.expiresAtMs, NOW + HORIZON_MS) + REVOCATION_RETENTION_ALLOWANCE_MS,
			),
		});
		expect(Object.isFrozen(scripted.decisions[0]?.family)).toBe(true);
	});

	it("leaves a record a concurrent revocation already revoked, and succeeds", async () => {
		const alreadyRevoked: RefreshTokenFamily = Object.freeze({
			familyId: "fam-race",
			activeJti: REVOKED_WITHOUT_RECORD_JTI,
			revoked: true,
			expiresAtMs: NOW + HORIZON_MS,
		});
		const scripted = scriptedStore(["not-found", alreadyRevoked], [duplicate()]);

		await expect(revocationOver(scripted.store).revokeFamily("fam-race")).resolves.toBeUndefined();

		expect(scripted.updatePasses()).toBe(2);
		expect(scripted.registrations()).toBe(1);
		expect(scripted.decisions).toEqual([{ action: "abort" }]);
	});

	for (const [label, refusal] of [
		[
			"a RefreshTokenStorageError of another reason",
			new RefreshTokenStorageError({ reason: "corrupt-data" }),
		],
		["an error that is not the store's own", new Error("connect ECONNREFUSED 127.0.0.1:6379")],
	] as const) {
		it(`propagates ${label} from the registration unchanged, without a second pass`, async () => {
			const scripted = scriptedStore(["not-found", "not-found"], [refusal]);

			const outcome = await revocationOver(scripted.store)
				.revokeFamily("fam-race")
				.catch((err: unknown) => err);

			expect(outcome).toBe(refusal);
			expect(scripted.updatePasses()).toBe(1);
			expect(scripted.registrations()).toBe(1);
		});
	}

	it("gives up with conflict-exhausted when both registrations collide and both passes find nothing", async () => {
		const scripted = scriptedStore(["not-found", "not-found"], [duplicate(), duplicate()]);

		const outcome = await revocationOver(scripted.store)
			.revokeFamily("fam-race")
			.catch((err: unknown) => err);

		expect(outcome).toBeInstanceOf(RefreshTokenStorageError);
		expect(outcome).toMatchObject({ reason: "conflict-exhausted" });
		expect(scripted.updatePasses()).toBe(2);
		expect(scripted.registrations()).toBe(2);
	});
});
