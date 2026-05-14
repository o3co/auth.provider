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
import { beforeEach, describe, expect, it } from "vitest";
import { WebAuthnCredentialStorageError } from "../errors.mjs";
import type { WebAuthnCredentialStore } from "../types.mjs";

export interface WebAuthnCredentialStoreContractFactory {
	/** Create a fresh, empty WebAuthnCredentialStore for one test. */
	create(): Promise<WebAuthnCredentialStore> | WebAuthnCredentialStore;
	/** Optional: tear down (close client, etc.) after each test. */
	teardown?(store: WebAuthnCredentialStore): Promise<void> | void;
}

/**
 * Adapter contract suite for WebAuthnCredentialStore. Memory + future adapters
 * call this and MUST pass identically (parity is the whole point of having
 * multiple adapters share one contract).
 *
 * Pattern mirrors AccessTokenDenylistContract / ChallengeStoreContract.
 */
export function runWebAuthnCredentialStoreContract(
	name: string,
	factory: WebAuthnCredentialStoreContractFactory,
): void {
	const sample = (
		overrides: Partial<Parameters<WebAuthnCredentialStore["registerCredential"]>[0]> = {},
	) => ({
		userId: "u-opaque-1",
		credentialId: "cid-1",
		publicKey: new Uint8Array([1, 2, 3]),
		signCount: 0,
		backedUp: false,
		createdAt: new Date("2026-05-12T00:00:00Z"),
		...overrides,
	});

	describe(`WebAuthnCredentialStore contract (${name})`, () => {
		let store: WebAuthnCredentialStore;

		beforeEach(async () => {
			store = await factory.create();
		});

		it("kind is a non-empty string", () => {
			expect(typeof store.kind).toBe("string");
			expect(store.kind.length).toBeGreaterThan(0);
		});

		it("findByCredentialId returns null when absent", async () => {
			expect(await store.findByCredentialId("missing")).toBeNull();
		});

		it("registerCredential then findByCredentialId", async () => {
			await store.registerCredential(sample());
			const found = await store.findByCredentialId("cid-1");
			expect(found?.userId).toBe("u-opaque-1");
		});

		it("listByUserId returns all credentials for a user", async () => {
			await store.registerCredential(sample());
			await store.registerCredential(sample({ credentialId: "cid-2" }));
			await store.registerCredential(sample({ userId: "u-2", credentialId: "cid-3" }));
			const got = await store.listByUserId("u-opaque-1");
			expect(got.map((c) => c.credentialId).sort()).toEqual(["cid-1", "cid-2"]);
		});

		it("registerCredential throws WebAuthnCredentialStorageError(duplicate-credential) on collision", async () => {
			await store.registerCredential(sample());
			let caught: unknown;
			try {
				await store.registerCredential(
					sample({ publicKey: new Uint8Array([9, 9, 9]), userId: "u-attacker" }),
				);
			} catch (err) {
				caught = err;
			}
			expect(caught).toBeInstanceOf(WebAuthnCredentialStorageError);
			expect((caught as WebAuthnCredentialStorageError).reason).toBe("duplicate-credential");
		});

		it("failed registerCredential preserves existing record unchanged (atomicity)", async () => {
			await store.registerCredential(sample());
			try {
				await store.registerCredential(
					sample({ publicKey: new Uint8Array([9, 9, 9]), userId: "u-attacker" }),
				);
			} catch {
				// expected
			}
			const found = await store.findByCredentialId("cid-1");
			expect(found?.userId).toBe("u-opaque-1");
			expect(Array.from(found?.publicKey ?? [])).toEqual([1, 2, 3]);
			// byUserId index for the original owner still has exactly this record;
			// the attacker's userId index must NOT have leaked an entry.
			expect((await store.listByUserId("u-opaque-1")).length).toBe(1);
			expect((await store.listByUserId("u-attacker")).length).toBe(0);
		});

		// Mirrors the registerFamily concurrent contract at
		// refresh-token-family/__tests__/adapters.contract.mts:170. The interface
		// JSDoc promises "N concurrent calls MUST result in exactly one success
		// and N-1 throws" — this test falsifies adapters that implement non-atomic
		// upsert (e.g. SQL INSERT without UNIQUE constraint, Redis SET without NX).
		it("concurrent registerCredential for same credentialId: exactly one success, N-1 duplicate-credential", async () => {
			const N = 50;
			const settled = await Promise.allSettled(
				Array.from({ length: N }, (_, i) => store.registerCredential(sample({ userId: `u-${i}` }))),
			);
			const successes = settled.filter((s) => s.status === "fulfilled").length;
			const dupes = settled.filter(
				(s) =>
					s.status === "rejected" &&
					s.reason instanceof WebAuthnCredentialStorageError &&
					s.reason.reason === "duplicate-credential",
			).length;
			expect(successes).toBe(1);
			expect(dupes).toBe(N - 1);
			// Exactly one credential record persisted under cid-1.
			const found = await store.findByCredentialId("cid-1");
			expect(found).not.toBeNull();
		});

		it("updateSignCount returns true on CAS match, increments", async () => {
			await store.registerCredential(sample({ signCount: 5 }));
			const ok = await store.updateSignCount("cid-1", {
				expectedCurrentSignCount: 5,
				newSignCount: 6,
				lastUsedAt: new Date(),
			});
			expect(ok).toBe(true);
			const got = await store.findByCredentialId("cid-1");
			expect(got?.signCount).toBe(6);
		});

		it("updateSignCount returns false on CAS mismatch (concurrent assertion race)", async () => {
			await store.registerCredential(sample({ signCount: 5 }));
			const ok = await store.updateSignCount("cid-1", {
				expectedCurrentSignCount: 4,
				newSignCount: 5,
				lastUsedAt: new Date(),
			});
			expect(ok).toBe(false);
			const got = await store.findByCredentialId("cid-1");
			expect(got?.signCount).toBe(5); // unchanged
		});

		it("remove deletes the record", async () => {
			await store.registerCredential(sample());
			await store.remove("cid-1");
			expect(await store.findByCredentialId("cid-1")).toBeNull();
		});
	});
}
