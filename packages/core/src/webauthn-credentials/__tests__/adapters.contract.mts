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
	const sample = (overrides: Partial<Parameters<WebAuthnCredentialStore["put"]>[0]> = {}) => ({
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

		it("put then findByCredentialId", async () => {
			await store.put(sample());
			const found = await store.findByCredentialId("cid-1");
			expect(found?.userId).toBe("u-opaque-1");
		});

		it("listByUserId returns all credentials for a user", async () => {
			await store.put(sample());
			await store.put(sample({ credentialId: "cid-2" }));
			await store.put(sample({ userId: "u-2", credentialId: "cid-3" }));
			const got = await store.listByUserId("u-opaque-1");
			expect(got.map((c) => c.credentialId).sort()).toEqual(["cid-1", "cid-2"]);
		});

		it("updateSignCount returns true on CAS match, increments", async () => {
			await store.put(sample({ signCount: 5 }));
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
			await store.put(sample({ signCount: 5 }));
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
			await store.put(sample());
			await store.remove("cid-1");
			expect(await store.findByCredentialId("cid-1")).toBeNull();
		});
	});
}
