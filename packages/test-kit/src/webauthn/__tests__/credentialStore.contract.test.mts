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
 * The WebAuthn credential store's contract suite, run over core's in-process store. Each broken
 * store below is refused by the case that describes what it breaks, so the suite is not vacuous.
 */

import {
	createMemoryWebAuthnCredentialStore,
	type WebAuthnCredential,
	WebAuthnCredentialStorageError,
	type WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import {
	type ContractCase,
	type WebAuthnCredentialStoreHarness,
	webAuthnCredentialStoreContract,
} from "#/index.mjs";

describe("webAuthnCredentialStoreContract over core's in-process store", () => {
	for (const contractCase of webAuthnCredentialStoreContract({
		build: async () => ({ store: createMemoryWebAuthnCredentialStore() }),
	})) {
		it(contractCase.name, contractCase.run);
	}
});

const ONE_USER =
	"a credential id belongs to one user: registering one another user holds throws duplicate-credential, and changes nothing";
const NO_REUPSERT =
	"registering a credential id its own user holds throws duplicate-credential, and changes nothing";
const ONE_OF_CONCURRENT =
	"lets exactly one of N concurrent registrations of one credential id through, the rest throwing duplicate-credential, and keeps that one's";
const SIGN_COUNT_REFUSED =
	"refuses a sign count update at another current count: false, and the count unchanged";
const REMOVED = "removes a credential: it is found no more";

/** Core's in-process store with `change` laid over it. */
function broken(
	change: (store: WebAuthnCredentialStore) => Partial<WebAuthnCredentialStore>,
): WebAuthnCredentialStoreHarness {
	const store = createMemoryWebAuthnCredentialStore();
	return { store: { ...store, ...change(store) } };
}

/** The names of the cases that refuse the store `build` makes. */
async function refusedBy(build: () => WebAuthnCredentialStoreHarness): Promise<string[]> {
	const refused: string[] = [];
	for (const contractCase of webAuthnCredentialStoreContract({ build: async () => build() })) {
		try {
			await contractCase.run();
		} catch {
			refused.push(contractCase.name);
		}
	}
	return refused;
}

describe("the suite refuses a store that breaks the contract", () => {
	it("one that lets a registration take a credential id another user holds", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				registerCredential: async (record) => {
					await store.remove(record.credentialId);
					await store.registerCredential(record);
				},
			})),
		);
		expect(refused).toContain(ONE_USER);
	});

	it("one that refuses a registration of a held credential id with an error other than duplicate-credential", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				registerCredential: async (record) => {
					try {
						await store.registerCredential(record);
					} catch {
						throw new Error("the credential id is taken");
					}
				},
			})),
		);
		expect(refused).toContain(ONE_USER);
	});

	it("one whose refused registration lists the credential under the refused user too", async () => {
		const refused = await refusedBy(() =>
			broken((store) => {
				const listed = new Map<string, readonly string[]>();
				return {
					registerCredential: async (record) => {
						listed.set(record.userId, [...(listed.get(record.userId) ?? []), record.credentialId]);
						await store.registerCredential(record);
					},
					listByUserId: async (userId) => {
						const found = await Promise.all(
							(listed.get(userId) ?? []).map((id) => store.findByCredentialId(id)),
						);
						return found.filter(
							(credential): credential is WebAuthnCredential => credential !== null,
						);
					},
				};
			}),
		);
		expect(refused).toContain(ONE_USER);
	});

	it("one that lets a user register a credential id it holds again, replacing it", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				registerCredential: async (record) => {
					const held = await store.findByCredentialId(record.credentialId);
					if (held?.userId === record.userId) await store.remove(record.credentialId);
					await store.registerCredential(record);
				},
			})),
		);
		expect(refused).toContain(NO_REUPSERT);
		expect(refused).not.toContain(ONE_USER);
	});

	it("one whose check for a held credential id and whose insert are two steps", async () => {
		const refused = await refusedBy(() =>
			broken((store) => {
				const held = new Map<string, WebAuthnCredential>();
				return {
					registerCredential: async (record) => {
						if (held.has(record.credentialId)) {
							throw new WebAuthnCredentialStorageError({ reason: "duplicate-credential" });
						}
						await Promise.resolve();
						held.set(record.credentialId, record);
					},
					findByCredentialId: async (credentialId) => held.get(credentialId) ?? null,
					listByUserId: async (userId) =>
						[...held.values()].filter((credential) => credential.userId === userId),
					remove: async (credentialId) => {
						held.delete(credentialId);
					},
					updateSignCount: store.updateSignCount,
				};
			}),
		);
		expect(refused).toContain(ONE_OF_CONCURRENT);
	});

	it("one whose sign count update ignores the count it expects", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				updateSignCount: async (credentialId, args) => {
					const current = await store.findByCredentialId(credentialId);
					return current === null
						? false
						: store.updateSignCount(credentialId, {
								...args,
								expectedCurrentSignCount: current.signCount,
							});
				},
			})),
		);
		expect(refused).toContain(SIGN_COUNT_REFUSED);
	});

	it("one whose removal leaves the credential", async () => {
		const refused = await refusedBy(() => broken(() => ({ remove: async () => {} })));
		expect(refused).toContain(REMOVED);
	});
});

describe("the suite's cases", () => {
	it("are typed as core's ContractCase, which the kit re-exports", () => {
		expectTypeOf(
			webAuthnCredentialStoreContract({
				build: async () => ({ store: createMemoryWebAuthnCredentialStore() }),
			}),
		).toEqualTypeOf<readonly ContractCase[]>();
	});
});

describe("each case", () => {
	it("builds a harness of its own and closes it, whether it passes or fails", async () => {
		let built = 0;
		let closed = 0;
		const failed: string[] = [];
		// A store whose removal leaves the credential: the removal's case fails, the others pass.
		const cases = webAuthnCredentialStoreContract({
			build: async () => {
				built += 1;
				return {
					store: { ...createMemoryWebAuthnCredentialStore(), remove: async () => {} },
					close: async () => {
						closed += 1;
					},
				};
			},
		});
		for (const contractCase of cases) {
			await contractCase.run().catch(() => failed.push(contractCase.name));
		}
		expect(failed).toEqual([REMOVED]);
		expect(built).toBe(cases.length);
		expect(closed).toBe(cases.length);
	});
});
