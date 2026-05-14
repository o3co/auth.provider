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
import { createMemoryWebAuthnCredentialStore } from "../memory.mjs";

const sample = (overrides = {}) => ({
	userId: "u-opaque-1",
	credentialId: "cid-1",
	publicKey: new Uint8Array([1, 2, 3]),
	signCount: 0,
	backedUp: false,
	createdAt: new Date("2026-05-12T00:00:00Z"),
	...overrides,
});

describe("createMemoryWebAuthnCredentialStore", () => {
	it("kind is 'memory'", () => {
		expect(createMemoryWebAuthnCredentialStore().kind).toBe("memory");
	});
	it("findByCredentialId returns null when absent", async () => {
		const s = createMemoryWebAuthnCredentialStore();
		expect(await s.findByCredentialId("missing")).toBeNull();
	});
	it("put then find", async () => {
		const s = createMemoryWebAuthnCredentialStore();
		await s.put(sample());
		const found = await s.findByCredentialId("cid-1");
		expect(found?.userId).toBe("u-opaque-1");
	});
	it("listByUserId returns all credentials for a user", async () => {
		const s = createMemoryWebAuthnCredentialStore();
		await s.put(sample());
		await s.put(sample({ credentialId: "cid-2" }));
		await s.put(sample({ userId: "u-2", credentialId: "cid-3" }));
		const got = await s.listByUserId("u-opaque-1");
		expect(got.map((c) => c.credentialId).sort()).toEqual(["cid-1", "cid-2"]);
	});
	it("updateSignCount returns true on CAS match, increments", async () => {
		const s = createMemoryWebAuthnCredentialStore();
		await s.put(sample({ signCount: 5 }));
		const ok = await s.updateSignCount("cid-1", {
			expectedCurrentSignCount: 5,
			newSignCount: 6,
			lastUsedAt: new Date(),
		});
		expect(ok).toBe(true);
		const got = await s.findByCredentialId("cid-1");
		expect(got?.signCount).toBe(6);
	});
	it("updateSignCount returns false on CAS mismatch (concurrent assertion race)", async () => {
		const s = createMemoryWebAuthnCredentialStore();
		await s.put(sample({ signCount: 5 }));
		const ok = await s.updateSignCount("cid-1", {
			expectedCurrentSignCount: 4,
			newSignCount: 5,
			lastUsedAt: new Date(),
		});
		expect(ok).toBe(false);
		const got = await s.findByCredentialId("cid-1");
		expect(got?.signCount).toBe(5); // unchanged
	});
	it("remove deletes the record", async () => {
		const s = createMemoryWebAuthnCredentialStore();
		await s.put(sample());
		await s.remove("cid-1");
		expect(await s.findByCredentialId("cid-1")).toBeNull();
	});
});
