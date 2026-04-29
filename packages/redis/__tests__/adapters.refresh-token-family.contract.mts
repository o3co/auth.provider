/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import {
	type RefreshTokenFamily,
	type RefreshTokenFamilyStore,
	RefreshTokenStorageError,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

/**
 * Factory shape accepted by the contract suite. Allows per-test prefixing
 * for the Redis adapter (avoids cross-test key collision in the shared
 * container) while letting the memory adapter just return a fresh instance.
 */
export type RefreshTokenFamilyStoreContractFactory = () => Promise<RefreshTokenFamilyStore>;

const FUTURE = (): Date => new Date(Date.now() + 60_000);
const PAST = (): Date => new Date(Date.now() - 1);

const FAMILY = (overrides: Partial<RefreshTokenFamily> = {}): RefreshTokenFamily => ({
	familyId: overrides.familyId ?? "fam-1",
	activeJti: overrides.activeJti ?? "jti-initial",
	revoked: overrides.revoked ?? false,
	expiresAt: overrides.expiresAt ?? FUTURE(),
});

export function runRefreshTokenFamilyStoreContract(
	factory: RefreshTokenFamilyStoreContractFactory,
): void {
	describe("RefreshTokenFamilyStore contract", () => {
		it("registerFamily then findFamily returns the family", async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			const found = await store.findFamily(fam.familyId);
			expect(found).not.toBeNull();
			expect(found?.familyId).toBe(fam.familyId);
			expect(found?.activeJti).toBe(fam.activeJti);
			expect(found?.revoked).toBe(false);
		});

		it("registerFamily throws duplicate-family on existing entry", async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			await expect(store.registerFamily(fam)).rejects.toMatchObject({
				name: "RefreshTokenStorageError",
				reason: "duplicate-family",
			});
		});

		it("registerFamily throws duplicate-family even if existing entry is revoked", async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			await store.updateFamily(fam.familyId, (current) => ({ ...current, revoked: true }));
			await expect(store.registerFamily(fam)).rejects.toMatchObject({
				name: "RefreshTokenStorageError",
				reason: "duplicate-family",
			});
		});

		it("registerFamily throws expired-at-issue when expiresAt is past", async () => {
			const store = await factory();
			const fam = FAMILY({ expiresAt: PAST() });
			await expect(store.registerFamily(fam)).rejects.toMatchObject({
				name: "RefreshTokenStorageError",
				reason: "expired-at-issue",
			});
		});

		it("findFamily returns null for non-existent familyId", async () => {
			const store = await factory();
			expect(await store.findFamily("never-registered")).toBeNull();
		});

		it("updateFamily returns not-found for non-existent familyId (does not invoke updater)", async () => {
			const store = await factory();
			let updaterCalled = false;
			const result = await store.updateFamily("ghost-id", (cur) => {
				updaterCalled = true;
				return cur;
			});
			expect(result.outcome).toBe("not-found");
			expect(updaterCalled).toBe(false);
		});

		it("updateFamily returns aborted when updater returns null", async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			const result = await store.updateFamily(fam.familyId, () => null);
			expect(result.outcome).toBe("aborted");
			const after = await store.findFamily(fam.familyId);
			expect(after?.activeJti).toBe(fam.activeJti); // unchanged
		});

		it("updateFamily returns committed with the new family on commit", async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			const result = await store.updateFamily(fam.familyId, (current) => ({
				...current,
				activeJti: "jti-rotated",
			}));
			expect(result.outcome).toBe("committed");
			if (result.outcome === "committed") {
				expect(result.family.activeJti).toBe("jti-rotated");
			}
			const after = await store.findFamily(fam.familyId);
			expect(after?.activeJti).toBe("jti-rotated");
		});

		it("updateFamily can flip revoked to true and persist", async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			await store.updateFamily(fam.familyId, (current) => ({ ...current, revoked: true }));
			const after = await store.findFamily(fam.familyId);
			expect(after?.revoked).toBe(true);
		});

		it("findFamily returns null for expired family (lazy GC)", async () => {
			const store = await factory();
			const fam = FAMILY({ expiresAt: new Date(Date.now() + 50) });
			await store.registerFamily(fam);
			await new Promise((r) => setTimeout(r, 100));
			expect(await store.findFamily(fam.familyId)).toBeNull();
		});

		it("updateFamily returns not-found for expired family", async () => {
			const store = await factory();
			const fam = FAMILY({ expiresAt: new Date(Date.now() + 50) });
			await store.registerFamily(fam);
			await new Promise((r) => setTimeout(r, 100));
			const result = await store.updateFamily(fam.familyId, (cur) => cur);
			expect(result.outcome).toBe("not-found");
		});

		it("updateFamily throws expired-at-issue when updater returns past expiresAt (fail-closed parity with registerFamily)", async () => {
			// Both adapters must fail-closed when the updater returns a family whose
			// expiresAt is already in the past. Without this, memory and Redis
			// adapters silently diverge: memory would commit a dead-on-arrival entry
			// (lazy-GC'd on next read) while Redis would map newTtlMs <= 0 to
			// not-found. Symmetric with registerFamily's expired-at-issue throw.
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			await expect(
				store.updateFamily(fam.familyId, (current) => ({
					...current,
					expiresAt: new Date(Date.now() - 1),
				})),
			).rejects.toMatchObject({
				name: "RefreshTokenStorageError",
				reason: "expired-at-issue",
			});
		});

		it("concurrent registerFamily for same familyId: exactly one success, N-1 duplicate-family", async () => {
			const store = await factory();
			const N = 50;
			const fam = FAMILY();
			const settled = await Promise.allSettled(
				Array.from({ length: N }, () => store.registerFamily(fam)),
			);
			const successes = settled.filter((s) => s.status === "fulfilled").length;
			const dupes = settled.filter(
				(s) =>
					s.status === "rejected" &&
					s.reason instanceof RefreshTokenStorageError &&
					s.reason.reason === "duplicate-family",
			).length;
			expect(successes).toBe(1);
			expect(dupes).toBe(N - 1);
		});

		it("concurrent updateFamily commits exactly one + rest abort or conflict-exhaust (sum=N)", async () => {
			const store = await factory();
			const N = 20;
			const fam = FAMILY({ activeJti: "jti-0" });
			await store.registerFamily(fam);

			// All N updaters try to rotate from "jti-0" → "jti-i". Exactly one observes
			// the initial state and commits; the rest re-read post-commit (activeJti
			// already "jti-X") and either abort (their updater returns null when the
			// previousJti precondition fails) or retry-exhaust under contention.
			const settled = await Promise.allSettled(
				Array.from({ length: N }, (_, i) =>
					store.updateFamily(fam.familyId, (current) => {
						if (current.activeJti !== "jti-0") return null; // abort: precondition lost
						return { ...current, activeJti: `jti-${i + 1}` };
					}),
				),
			);

			let committed = 0;
			let aborted = 0;
			let exhausted = 0;
			for (const s of settled) {
				if (s.status === "fulfilled") {
					if (s.value.outcome === "committed") committed++;
					else if (s.value.outcome === "aborted") aborted++;
					else throw new Error(`unexpected outcome: ${JSON.stringify(s.value)}`);
				} else if (
					s.reason instanceof RefreshTokenStorageError &&
					s.reason.reason === "conflict-exhausted"
				) {
					exhausted++;
				} else {
					throw new Error(`unexpected rejection: ${String(s.reason)}`);
				}
			}
			expect(committed).toBe(1);
			expect(aborted + exhausted).toBe(N - 1);
		});
	});
}
