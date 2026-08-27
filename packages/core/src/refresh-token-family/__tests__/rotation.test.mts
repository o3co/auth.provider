/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { createMemoryRefreshTokenFamilyStore } from "../adapters/memory.mjs";
import { RefreshTokenStorageError } from "../errors.mjs";
import { createRefreshTokenFamilyRotation } from "../rotation.mjs";
import type { RefreshTokenFamilyStore } from "../types.mjs";

const FUTURE = (): number => Date.now() + 60_000;

/**
 * Wrap a store so the test can count how many `updateFamily` round-trips a
 * single `rotate` costs. #274 is precisely a "one operation or two?" question,
 * so the count is the assertion — not an implementation detail.
 */
const counting = (
	store: RefreshTokenFamilyStore,
): { store: RefreshTokenFamilyStore; calls: () => number; reset: () => void } => {
	let calls = 0;
	return {
		store: {
			...store,
			updateFamily: (familyId, updater) => {
				calls++;
				return store.updateFamily(familyId, updater);
			},
		},
		calls: () => calls,
		reset: () => {
			calls = 0;
		},
	};
};

describe("createRefreshTokenFamilyRotation", () => {
	it("register then findFamily shows the new family", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());
		const fam = await store.findFamily("fam-1");
		expect(fam).not.toBeNull();
		expect(fam?.activeJti).toBe("jti-1");
		expect(fam?.revoked).toBe(false);
	});

	it("register throws duplicate-family on second call", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());
		await expect(rotation.register("jti-2", "fam-1", FUTURE())).rejects.toMatchObject({
			name: "RefreshTokenStorageError",
			reason: "duplicate-family",
		});
	});

	it("register throws expired-at-issue when expiresAt is past", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await expect(rotation.register("jti-1", "fam-1", Date.now() - 1)).rejects.toBeInstanceOf(
			RefreshTokenStorageError,
		);
	});

	it("rotate returns 'rotated' when previousJti matches and family is healthy", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());
		const out = await rotation.rotate("jti-1", "jti-2", "fam-1", FUTURE());
		expect(out.outcome).toBe("rotated");
		const after = await store.findFamily("fam-1");
		expect(after?.activeJti).toBe("jti-2");
	});

	it("rotate returns 'replayed' when previousJti does NOT match the active jti", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());
		// Try to rotate using a stale previousJti.
		const out = await rotation.rotate("jti-stale", "jti-2", "fam-1", FUTURE());
		expect(out.outcome).toBe("replayed");
		const after = await store.findFamily("fam-1");
		expect(after?.activeJti).toBe("jti-1"); // unchanged
	});

	// -----------------------------------------------------------------------
	// #274: replay detection and family revocation are ONE compare-and-swap.
	//
	// Before this, `rotate` aborted the CAS on replay and left revocation to
	// the caller as a second write. Between those two writes a sibling holding
	// the still-active token could rotate and walk away with tokens, partially
	// defeating the whole-family revocation RFC 6819 §5.2.2.3 requires.
	//
	// The fix is structural, so the assertions are structural: the replay path
	// must cost exactly ONE store operation, and the family must already be
	// revoked by the time `rotate` returns. There is then no second write for
	// anything to race with.
	// -----------------------------------------------------------------------
	describe("#274: replay detection and family revocation are one atomic write", () => {
		it("revokes the family in the SAME updateFamily call that detects the replay", async () => {
			const store = createMemoryRefreshTokenFamilyStore();
			const probe = counting(store);
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: probe.store });
			await rotation.register("jti-1", "fam-1", FUTURE());
			probe.reset();

			const out = await rotation.rotate("jti-stale", "jti-2", "fam-1", FUTURE());

			expect(out.outcome).toBe("replayed");
			// One operation, not two: detection and revocation are indivisible.
			expect(probe.calls()).toBe(1);
			// And the revocation is already durable when rotate returns — the
			// caller does not have to perform it, so there is no window.
			const after = await store.findFamily("fam-1");
			expect(after?.revoked).toBe(true);
			// The replaying jti is NOT installed as active, and the jti that was
			// active at revocation time is retained for audit (A3 §5.1).
			expect(after?.activeJti).toBe("jti-1");
		});

		it("reports familyRevoked on the replayed outcome so the caller can skip its own revoke", async () => {
			const store = createMemoryRefreshTokenFamilyStore();
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
			await rotation.register("jti-1", "fam-1", FUTURE());

			const out = await rotation.rotate("jti-stale", "jti-2", "fam-1", FUTURE());

			expect(out.outcome).toBe("replayed");
			if (out.outcome !== "replayed") return; // type narrowing
			expect(out.familyRevoked).toBe(true);
		});

		it("does not write again when the family is ALREADY revoked (revoked outcome still aborts)", async () => {
			// The already-revoked branch has nothing to revoke, so it must stay a
			// no-op abort. Committing there would rewrite an unchanged aggregate
			// on every rejected request — a write amplification on the exact path
			// an attacker can drive.
			const store = createMemoryRefreshTokenFamilyStore();
			const probe = counting(store);
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: probe.store });
			await rotation.register("jti-1", "fam-1", FUTURE());
			await rotation.rotate("jti-stale", "jti-2", "fam-1", FUTURE()); // revokes
			const revokedAt = await store.findFamily("fam-1");
			probe.reset();

			const out = await rotation.rotate("jti-1", "jti-3", "fam-1", FUTURE());

			expect(out.outcome).toBe("revoked");
			expect(probe.calls()).toBe(1);
			const after = await store.findFamily("fam-1");
			expect(after?.activeJti).toBe(revokedAt?.activeJti);
			expect(after?.revoked).toBe(true);
		});

		it("two concurrent redemptions of the same token: exactly one rotates, and the family ends revoked", async () => {
			// The race #274 describes, expressed at the rotation surface: two
			// requests redeem the same refresh token. One is a legitimate
			// rotation; the other is, by definition, a replay. Whichever order
			// the store serialises them in, exactly one may succeed and the
			// family MUST be revoked once the loser is classified.
			const store = createMemoryRefreshTokenFamilyStore();
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
			await rotation.register("jti-1", "fam-1", FUTURE());

			const [a, b] = await Promise.all([
				rotation.rotate("jti-1", "jti-2a", "fam-1", FUTURE()),
				rotation.rotate("jti-1", "jti-2b", "fam-1", FUTURE()),
			]);

			expect([a.outcome, b.outcome].sort()).toEqual(["replayed", "rotated"]);
			expect((await store.findFamily("fam-1"))?.revoked).toBe(true);
		});

		it("N concurrent redemptions of the same token: exactly one rotates, the rest are rejected, family revoked", async () => {
			const store = createMemoryRefreshTokenFamilyStore();
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
			await rotation.register("jti-1", "fam-1", FUTURE());

			const N = 20;
			const outcomes = await Promise.all(
				Array.from({ length: N }, (_, i) =>
					rotation.rotate("jti-1", `jti-${i}`, "fam-1", FUTURE()),
				),
			);

			const rotated = outcomes.filter((o) => o.outcome === "rotated").length;
			const rejected = outcomes.filter(
				(o) => o.outcome === "replayed" || o.outcome === "revoked",
			).length;
			expect(rotated).toBe(1);
			expect(rejected).toBe(N - 1);
			expect((await store.findFamily("fam-1"))?.revoked).toBe(true);
		});

		it("a sibling holding the freshly-rotated token cannot rotate once a replay has been classified", async () => {
			// The concrete attack the two-write version allowed: the replay is
			// detected, and before the family is revoked the sibling redeems the
			// currently-active token successfully. With detection and revocation
			// fused, the sibling's rotation is either ordered BEFORE the replay
			// classification (and is a legitimate rotation) or sees a revoked
			// family. It can never land in between.
			const store = createMemoryRefreshTokenFamilyStore();
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
			await rotation.register("jti-1", "fam-1", FUTURE());
			await rotation.rotate("jti-1", "jti-2", "fam-1", FUTURE()); // legitimate rotation

			// Attacker replays the rotated-out jti-1.
			const replay = await rotation.rotate("jti-1", "jti-evil", "fam-1", FUTURE());
			expect(replay.outcome).toBe("replayed");

			// The honest sibling still holds jti-2, the jti that was active. It
			// must now be refused, because the family is already revoked.
			const sibling = await rotation.rotate("jti-2", "jti-3", "fam-1", FUTURE());
			expect(sibling.outcome).toBe("revoked");
		});
	});

	it("rotate returns 'revoked' when family is revoked (regardless of previousJti match)", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());
		await store.updateFamily("fam-1", (cur) => ({
			action: "commit",
			family: { ...cur, revoked: true },
		}));
		const out = await rotation.rotate("jti-1", "jti-2", "fam-1", FUTURE());
		expect(out.outcome).toBe("revoked");
	});

	it("rotate returns 'unknown_family' when family does not exist", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		const out = await rotation.rotate("jti-x", "jti-y", "ghost-fam", FUTURE());
		expect(out.outcome).toBe("unknown_family");
	});

	it("outcome objects are frozen at runtime", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());
		const rotated = await rotation.rotate("jti-1", "jti-2", "fam-1", FUTURE());
		expect(Object.isFrozen(rotated)).toBe(true);

		const replayed = await rotation.rotate("jti-stale", "jti-3", "fam-1", FUTURE());
		expect(Object.isFrozen(replayed)).toBe(true);

		const unknown = await rotation.rotate("jti-x", "jti-y", "ghost", FUTURE());
		expect(Object.isFrozen(unknown)).toBe(true);
	});

	// IH-13 (v0.5.1): RT family expiresAtMs is set ONCE at creation and
	// never extended on rotation (OAuth 2.1 BCP §4.14.1 absolute expiry).
	// `Math.min(requestedExpiresAtMs, current.expiresAtMs)` enforces the
	// ceiling. The committed value is exposed via the optional
	// `cappedExpiresAtMs` field on the "rotated" outcome.
	//
	// Test stability (Copilot review on PR #126): all ceilings here use
	// `>= 60s` so loaded CI runners cannot lazy-GC the family between
	// `register` and `rotate`/`findFamily`. The cap logic does not depend
	// on the absolute ceiling value — only on the relative ordering of
	// `ceiling` vs the rotation's requested expiry — so a 60s ceiling is
	// equivalent to a 1s ceiling for what these tests assert.
	describe("IH-13: absolute expiry cap (no sliding window)", () => {
		it("does not extend family expiresAtMs on rotation when caller requests later expiry", async () => {
			const store = createMemoryRefreshTokenFamilyStore();
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });

			const ceiling = Date.now() + 60_000; // 60s ceiling — CI-safe; see describe block comment
			await rotation.register("jti-1", "fam-1", ceiling);

			// Caller requests rotation with a much-later expiry (sliding-window
			// behaviour pre-IH-13). After the cap, the stored value MUST NOT
			// exceed the original ceiling.
			const later = Date.now() + 86_400_000; // 1 day
			const out = await rotation.rotate("jti-1", "jti-2", "fam-1", later);

			expect(out.outcome).toBe("rotated");
			const after = await store.findFamily("fam-1");
			expect(after?.expiresAtMs).toBeLessThanOrEqual(ceiling);
		});

		it("rotated outcome carries cappedExpiresAtMs equal to the committed family ceiling", async () => {
			const store = createMemoryRefreshTokenFamilyStore();
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });

			const ceiling = Date.now() + 60_000;
			await rotation.register("jti-1", "fam-1", ceiling);

			const later = Date.now() + 86_400_000;
			const out = await rotation.rotate("jti-1", "jti-2", "fam-1", later);

			expect(out.outcome).toBe("rotated");
			if (out.outcome !== "rotated") return; // type narrowing
			expect(out.cappedExpiresAtMs).toBeDefined();
			expect(out.cappedExpiresAtMs).toBeLessThanOrEqual(ceiling);

			// And matches the actually-stored value.
			const after = await store.findFamily("fam-1");
			expect(out.cappedExpiresAtMs).toBe(after?.expiresAtMs);
		});

		it("caller-supplied expiresAtMs is honoured when it is smaller than the ceiling", async () => {
			// The cap is a one-way clamp: requested > ceiling collapses to
			// ceiling, but requested < ceiling is honoured (the caller chose
			// to shrink the TTL — e.g., session-bound RT). This test guards
			// against an over-eager `Math.max` swap during refactor.
			const store = createMemoryRefreshTokenFamilyStore();
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });

			const ceiling = Date.now() + 86_400_000; // 1 day
			await rotation.register("jti-1", "fam-1", ceiling);

			// 30s — well above the lazy-GC window but still smaller than the
			// 1-day ceiling, exercising the requested-< -ceiling branch.
			const earlier = Date.now() + 30_000;
			const out = await rotation.rotate("jti-1", "jti-2", "fam-1", earlier);

			expect(out.outcome).toBe("rotated");
			if (out.outcome !== "rotated") return;
			expect(out.cappedExpiresAtMs).toBe(earlier);
		});
	});
});
