/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { createMemoryRefreshTokenFamilyStore } from "../adapters/memory.mjs";
import { RefreshTokenStorageError } from "../errors.mjs";
import { createRefreshTokenFamilyRotation } from "../rotation.mjs";

const FUTURE = (): number => Date.now() + 60_000;

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

	it("rotate returns 'revoked' when family is revoked (regardless of previousJti match)", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());
		await store.updateFamily("fam-1", (cur) => ({ ...cur, revoked: true }));
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
	describe("IH-13: absolute expiry cap (no sliding window)", () => {
		it("does not extend family expiresAtMs on rotation when caller requests later expiry", async () => {
			const store = createMemoryRefreshTokenFamilyStore();
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });

			const ceiling = Date.now() + 1000; // 1s ceiling
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

			const earlier = Date.now() + 1000; // 1s
			const out = await rotation.rotate("jti-1", "jti-2", "fam-1", earlier);

			expect(out.outcome).toBe("rotated");
			if (out.outcome !== "rotated") return;
			expect(out.cappedExpiresAtMs).toBe(earlier);
		});
	});
});
