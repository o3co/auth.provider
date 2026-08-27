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
import { describe, expect, it } from "vitest";
import { RefreshTokenStorageError } from "../errors.mjs";
import type { RefreshTokenFamily, RefreshTokenFamilyStore } from "../types.mjs";

/**
 * Factory shape accepted by the contract suite. Allows per-test prefixing
 * for the Redis adapter (avoids cross-test key collision in the shared
 * container) while letting the memory adapter just return a fresh instance.
 */
export type RefreshTokenFamilyStoreContractFactory = () => Promise<RefreshTokenFamilyStore>;

const FUTURE = (): number => Date.now() + 60_000;
const PAST = (): number => Date.now() - 1;

const FAMILY = (overrides: Partial<RefreshTokenFamily> = {}): RefreshTokenFamily => ({
	familyId: overrides.familyId ?? "fam-1",
	activeJti: overrides.activeJti ?? "jti-initial",
	revoked: overrides.revoked ?? false,
	expiresAtMs: overrides.expiresAtMs ?? FUTURE(),
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
			await store.updateFamily(fam.familyId, (current) => ({
				action: "commit",
				family: { ...current, revoked: true },
			}));
			await expect(store.registerFamily(fam)).rejects.toMatchObject({
				name: "RefreshTokenStorageError",
				reason: "duplicate-family",
			});
		});

		it("registerFamily throws expired-at-issue when expiresAtMs is past", async () => {
			const store = await factory();
			const fam = FAMILY({ expiresAtMs: PAST() });
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
				return { action: "commit", family: cur };
			});
			expect(result.outcome).toBe("not-found");
			expect(updaterCalled).toBe(false);
		});

		it('updateFamily returns aborted when the updater decides { action: "abort" }', async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			const result = await store.updateFamily(fam.familyId, () => ({ action: "abort" }));
			expect(result.outcome).toBe("aborted");
			const after = await store.findFamily(fam.familyId);
			expect(after?.activeJti).toBe(fam.activeJti); // unchanged
		});

		// #274: a decision carries an opaque `reason` back to the caller so a
		// wrapper can classify an outcome from INSIDE the atomic operation.
		// Without it, "committed" cannot distinguish an ordinary rotation from
		// a commit that exists to reject the request (a replay revocation),
		// and the only alternative — a closure variable read after the call —
		// is unsound under the CAS retry contract.
		it("updateFamily echoes the aborting decision's reason verbatim", async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			const result = await store.updateFamily(fam.familyId, () => ({
				action: "abort",
				reason: "caller-specific-abort",
			}));
			expect(result).toMatchObject({ outcome: "aborted", reason: "caller-specific-abort" });
		});

		it("updateFamily echoes the committing decision's reason verbatim", async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			const result = await store.updateFamily(fam.familyId, (current) => ({
				action: "commit",
				family: { ...current, revoked: true },
				reason: "caller-specific-commit",
			}));
			expect(result).toMatchObject({ outcome: "committed", reason: "caller-specific-commit" });
			// The reason is transport, not state: it must not be persisted.
			const after = await store.findFamily(fam.familyId);
			expect(after).not.toHaveProperty("reason");
			expect(after?.revoked).toBe(true);
		});

		it("updateFamily OMITS the reason key entirely when the decision carried none", async () => {
			// `reason` is optional, so "absent" and "present but undefined" must not
			// be the same value — a caller doing `"reason" in result` (or comparing
			// results structurally) can tell them apart, and an adapter that always
			// writes the key silently disagrees with its own contract.
			//
			// Asserted with `in` rather than `toEqual`, which treats a missing key
			// and an `undefined` value as equal and would pass against exactly the
			// shape this pins against.
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);

			const committed = await store.updateFamily(fam.familyId, (current) => ({
				action: "commit",
				family: { ...current, activeJti: "jti-no-reason" },
			}));
			expect(committed.outcome).toBe("committed");
			expect("reason" in committed).toBe(false);

			const aborted = await store.updateFamily(fam.familyId, () => ({ action: "abort" }));
			expect(aborted.outcome).toBe("aborted");
			expect("reason" in aborted).toBe(false);

			// not-found never invokes the updater, so there is no decision to echo.
			const missing = await store.updateFamily("never-registered-at-all", (current) => ({
				action: "commit",
				family: current,
			}));
			expect(missing.outcome).toBe("not-found");
			expect("reason" in missing).toBe(false);
		});

		it("updateFamily keeps the reason key present when the decision supplied one", async () => {
			// The mirror of the case above: an explicitly-supplied reason must
			// survive as an own property, so the conditional spread cannot be
			// "fixed" by dropping the field altogether.
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);

			const committed = await store.updateFamily(fam.familyId, (current) => ({
				action: "commit",
				family: { ...current, activeJti: "jti-with-reason" },
				reason: "present",
			}));
			expect("reason" in committed).toBe(true);

			const aborted = await store.updateFamily(fam.familyId, () => ({
				action: "abort",
				reason: "present",
			}));
			expect("reason" in aborted).toBe(true);
		});

		it("updateFamily returns committed with the new family on commit", async () => {
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			const result = await store.updateFamily(fam.familyId, (current) => ({
				action: "commit",
				family: { ...current, activeJti: "jti-rotated" },
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
			await store.updateFamily(fam.familyId, (current) => ({
				action: "commit",
				family: { ...current, revoked: true },
			}));
			const after = await store.findFamily(fam.familyId);
			expect(after?.revoked).toBe(true);
		});

		it("findFamily returns null for expired family (lazy GC)", async () => {
			const store = await factory();
			const fam = FAMILY({ expiresAtMs: Date.now() + 50 });
			await store.registerFamily(fam);
			await new Promise((r) => setTimeout(r, 100));
			expect(await store.findFamily(fam.familyId)).toBeNull();
		});

		it("updateFamily returns not-found for expired family", async () => {
			const store = await factory();
			const fam = FAMILY({ expiresAtMs: Date.now() + 50 });
			await store.registerFamily(fam);
			await new Promise((r) => setTimeout(r, 100));
			const result = await store.updateFamily(fam.familyId, (cur) => ({
				action: "commit",
				family: cur,
			}));
			expect(result.outcome).toBe("not-found");
		});

		it("updateFamily throws expired-at-issue when updater returns past expiresAtMs (fail-closed parity with registerFamily)", async () => {
			// Both adapters must fail-closed when the updater returns a family whose
			// expiresAtMs is already in the past. Without this, memory and Redis
			// adapters silently diverge: memory would commit a dead-on-arrival entry
			// (lazy-GC'd on next read) while Redis would map newTtlMs <= 0 to
			// not-found. Symmetric with registerFamily's expired-at-issue throw.
			const store = await factory();
			const fam = FAMILY();
			await store.registerFamily(fam);
			await expect(
				store.updateFamily(fam.familyId, (current) => ({
					action: "commit",
					family: { ...current, expiresAtMs: Date.now() - 1 },
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
						// abort: precondition lost
						if (current.activeJti !== "jti-0") return { action: "abort" };
						return { action: "commit", family: { ...current, activeJti: `jti-${i + 1}` } };
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
