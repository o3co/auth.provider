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
 * The contract suite of `WebAuthnCredentialStore`, for every adapter. The WebAuthn grant finds
 * the credential an assertion names by its id alone and signs in the user the record names, so
 * a credential id held by two users, or re-registered over its record, lets one account's key
 * answer for another's.
 *
 * Holds a store to: a non-empty `kind`; nothing found for an id it does not hold; a registered
 * credential found by its id, with the user, public key and sign count it was registered with;
 * every credential of a user listed, and no other user's; a credential id belonging to one
 * user — registering one another user holds, or its own user, throws
 * `WebAuthnCredentialStorageError` `duplicate-credential` and changes nothing; one of N
 * concurrent registrations of one id let through, the rest `duplicate-credential`, and the
 * record the one that went through; a sign count updated at the expected current count, and
 * refused, unchanged, at another; and a removed credential found no more. Each case builds a
 * fresh harness and closes it.
 */

import assert from "node:assert/strict";
import {
	type WebAuthnCredential,
	WebAuthnCredentialStorageError,
	type WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "@o3co/auth-provider-core/testing";

/** What one case runs over: a fresh, empty store. */
export interface WebAuthnCredentialStoreHarness {
	/** The store under test, holding nothing. */
	readonly store: WebAuthnCredentialStore;
	/** Releases what the store runs on once the case ends. */
	readonly close?: () => Promise<void>;
}

export interface WebAuthnCredentialStoreContractInput {
	/** Builds a fresh harness for each case. */
	readonly build: () => Promise<WebAuthnCredentialStoreHarness>;
}

/** Of the concurrent registrations of one credential id. */
const CONCURRENT = 50;

const CREDENTIAL = (overrides: Partial<WebAuthnCredential> = {}): WebAuthnCredential => ({
	userId: "u-opaque-1",
	credentialId: "cid-1",
	publicKey: new Uint8Array([1, 2, 3]),
	signCount: 0,
	backedUp: false,
	createdAt: new Date("2026-05-12T00:00:00Z"),
	...overrides,
});

/** Whether `err` is the store's refusal of a credential id it holds. */
const isDuplicate = (err: unknown): boolean =>
	err instanceof WebAuthnCredentialStorageError && err.reason === "duplicate-credential";

/** The ids of `credentials`, sorted. */
const idsOf = (credentials: readonly WebAuthnCredential[]): string[] =>
	credentials.map((credential) => credential.credentialId).sort();

/** That the store holds `cid-1` as {@link CREDENTIAL} registered it, for `u-opaque-1` alone. */
async function holdsTheFirst(store: WebAuthnCredentialStore, other: string): Promise<void> {
	const found = await store.findByCredentialId("cid-1");
	assert.equal(found?.userId, "u-opaque-1");
	assert.deepEqual(Array.from(found?.publicKey ?? []), [1, 2, 3]);
	assert.deepEqual(idsOf(await store.listByUserId("u-opaque-1")), ["cid-1"]);
	if (other !== "u-opaque-1") assert.deepEqual(await store.listByUserId(other), []);
}

/** A case that builds its harness, runs `body` over its store and closes it. */
function contractCase(
	input: WebAuthnCredentialStoreContractInput,
	name: string,
	body: (store: WebAuthnCredentialStore) => Promise<void>,
): ContractCase {
	return {
		name,
		run: async () => {
			const harness = await input.build();
			try {
				await body(harness.store);
			} finally {
				await harness.close?.();
			}
		},
	};
}

/** The cases of the WebAuthn credential store's contract over the harnesses `input` builds. */
export function webAuthnCredentialStoreContract(
	input: WebAuthnCredentialStoreContractInput,
): readonly ContractCase[] {
	const test = (name: string, body: (store: WebAuthnCredentialStore) => Promise<void>) =>
		contractCase(input, name, body);
	return [
		test("has a kind: a non-empty string", async (store) => {
			assert.equal(typeof store.kind, "string");
			assert.ok(store.kind.length > 0);
		}),

		test("finds nothing for a credential id it does not hold", async (store) => {
			assert.equal(await store.findByCredentialId("missing"), null);
		}),

		test("finds a registered credential by its id, with the user, public key and sign count it was registered with", async (store) => {
			await store.registerCredential(CREDENTIAL({ signCount: 7 }));
			const found = await store.findByCredentialId("cid-1");
			assert.equal(found?.credentialId, "cid-1");
			assert.equal(found?.userId, "u-opaque-1");
			assert.deepEqual(Array.from(found?.publicKey ?? []), [1, 2, 3]);
			assert.equal(found?.signCount, 7);
		}),

		test("lists every credential of a user, and no other user's", async (store) => {
			await store.registerCredential(CREDENTIAL());
			await store.registerCredential(CREDENTIAL({ credentialId: "cid-2" }));
			await store.registerCredential(CREDENTIAL({ userId: "u-2", credentialId: "cid-3" }));
			assert.deepEqual(idsOf(await store.listByUserId("u-opaque-1")), ["cid-1", "cid-2"]);
			assert.deepEqual(idsOf(await store.listByUserId("u-2")), ["cid-3"]);
		}),

		test("a credential id belongs to one user: registering one another user holds throws duplicate-credential, and changes nothing", async (store) => {
			await store.registerCredential(CREDENTIAL());
			await assert.rejects(
				store.registerCredential(
					CREDENTIAL({ userId: "u-attacker", publicKey: new Uint8Array([9, 9, 9]) }),
				),
				isDuplicate,
			);
			await holdsTheFirst(store, "u-attacker");
		}),

		test("registering a credential id its own user holds throws duplicate-credential, and changes nothing", async (store) => {
			await store.registerCredential(CREDENTIAL());
			await assert.rejects(
				store.registerCredential(CREDENTIAL({ publicKey: new Uint8Array([9, 9, 9]) })),
				isDuplicate,
			);
			await holdsTheFirst(store, "u-opaque-1");
		}),

		test("lets exactly one of N concurrent registrations of one credential id through, the rest throwing duplicate-credential, and keeps that one's", async (store) => {
			const settled = await Promise.allSettled(
				Array.from({ length: CONCURRENT }, (_, i) =>
					store.registerCredential(CREDENTIAL({ userId: `u-${i}` })),
				),
			);
			const through = settled.flatMap((outcome, i) =>
				outcome.status === "fulfilled" ? [`u-${i}`] : [],
			);
			const refused = settled.filter(
				(outcome) => outcome.status === "rejected" && isDuplicate(outcome.reason),
			);
			assert.equal(through.length, 1);
			assert.equal(refused.length, CONCURRENT - 1);
			assert.equal((await store.findByCredentialId("cid-1"))?.userId, through[0]);
		}),

		test("updates the sign count at the expected current count", async (store) => {
			await store.registerCredential(CREDENTIAL({ signCount: 5 }));
			const updated = await store.updateSignCount("cid-1", {
				expectedCurrentSignCount: 5,
				newSignCount: 6,
				lastUsedAt: new Date("2026-05-13T00:00:00Z"),
			});
			assert.equal(updated, true);
			assert.equal((await store.findByCredentialId("cid-1"))?.signCount, 6);
		}),

		test("refuses a sign count update at another current count: false, and the count unchanged", async (store) => {
			await store.registerCredential(CREDENTIAL({ signCount: 5 }));
			const updated = await store.updateSignCount("cid-1", {
				expectedCurrentSignCount: 4,
				newSignCount: 5,
				lastUsedAt: new Date("2026-05-13T00:00:00Z"),
			});
			assert.equal(updated, false);
			assert.equal((await store.findByCredentialId("cid-1"))?.signCount, 5);
		}),

		test("removes a credential: it is found no more", async (store) => {
			await store.registerCredential(CREDENTIAL());
			await store.remove("cid-1");
			assert.equal(await store.findByCredentialId("cid-1"), null);
		}),
	];
}
