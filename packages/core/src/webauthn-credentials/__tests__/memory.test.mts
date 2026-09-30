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

/**
 * What core's in-process `WebAuthnCredentialStore` and its module promise beyond the port's
 * contract suite, which the test kit (`webAuthnCredentialStoreContract`) runs over this store.
 */

import { describe, expect, it } from "vitest";
import { createMemoryWebAuthnCredentialStore } from "#/webauthn-credentials/memory.mjs";
import { memoryWebAuthnCredentialStoreModule } from "#/webauthn-credentials/module.mjs";

describe("the in-process WebAuthnCredentialStore", () => {
	it("is kind memory", () => {
		expect(createMemoryWebAuthnCredentialStore().kind).toBe("memory");
	});

	it("removes a credential id it does not hold as a no-op: what it holds stays", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.registerCredential({
			userId: "u-1",
			credentialId: "cid-1",
			publicKey: new Uint8Array([1, 2, 3]),
			signCount: 0,
			backedUp: false,
			createdAt: new Date("2026-05-12T00:00:00Z"),
		});

		await expect(store.remove("missing")).resolves.toBeUndefined();

		expect((await store.findByCredentialId("cid-1"))?.userId).toBe("u-1");
		expect(await store.listByUserId("u-1")).toHaveLength(1);
	});
});

describe("memoryWebAuthnCredentialStoreModule", () => {
	it("declares itself replica-unsafe, saying what forks per replica", () => {
		expect(memoryWebAuthnCredentialStoreModule.name).toBe("core-webauthn-credential-store-memory");
		expect(memoryWebAuthnCredentialStoreModule.replicaSafety?.unsafe).toBe(true);
		expect(memoryWebAuthnCredentialStoreModule.replicaSafety?.reason).toMatch(/fork per replica/);
	});
});
