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
 * The contract suite of `MfaFactorStore` (the MFA ADR's D7), for every
 * adapter. "Only zero records open a first binding" (the same ADR's F3) is
 * only as strong as the store: a record that comes back without a field, a
 * version that two writers both win, or a removal that reaches another
 * subject each loses or forges a factor.
 *
 * Holds a store to: nothing listed for a subject with none; a created record
 * listed whole, as plain data, its undefined fields named; `data` kept byte
 * for byte; every binding and any kind round-tripped; a duplicate
 * `(subject, id)` refused, the record kept, and one of N concurrent creates
 * let through; subjects kept apart; an update at the current version
 * replacing `data`, `label` and `lastUsedAt` and nothing else, at version
 * + 1, and clearing what it says `undefined`; `null` for a version that moved
 * or a record that is gone, nothing changed; a `RangeError` for an update at
 * `Number.MAX_SAFE_INTEGER`; one winner among N concurrent updates at one
 * version; removal of one record and of a subject's records, idempotent and
 * no further; and a removed record taken again. Every record id is 22
 * base64url characters, as the provider makes one. Each case builds a fresh
 * harness and closes it.
 */

import assert from "node:assert/strict";
import type { MfaFactorRecord, MfaFactorStore } from "@o3co/auth-provider-core";
import type { ContractCase } from "@o3co/auth-provider-core/testing";

/** What one case runs over: a fresh, empty store. */
export interface MfaFactorStoreHarness {
	/** The store under test, holding nothing. */
	readonly store: MfaFactorStore;
	/** Releases what the store runs on once the case ends. */
	readonly close?: () => Promise<void>;
}

export interface MfaFactorStoreContractInput {
	/** Builds a fresh harness for each case. */
	readonly build: () => Promise<MfaFactorStoreHarness>;
}

/** A factor id as the provider makes one: `name` padded to 22 base64url characters. */
const factorId = (name: string): string => name.padEnd(22, "A");

const FACTOR_1 = factorId("factor-1");
const FACTOR_2 = factorId("factor-2");

const RECORD = (overrides: Partial<MfaFactorRecord> = {}): MfaFactorRecord => ({
	id: FACTOR_1,
	subject: "user-1",
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: new Date("2026-09-02T00:00:00.000Z"),
	version: 1,
	data: "v2.opaque-sealed-data",
	...overrides,
});

const byId = (records: readonly MfaFactorRecord[]): MfaFactorRecord[] =>
	[...records].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

/** A case that builds its harness, runs `body` over its store and closes it. */
function contractCase(
	input: MfaFactorStoreContractInput,
	name: string,
	body: (store: MfaFactorStore) => Promise<void>,
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

/** The cases of the factor store's contract over the harnesses `input` builds. */
export function mfaFactorStoreContract(
	input: MfaFactorStoreContractInput,
): readonly ContractCase[] {
	const test = (name: string, body: (store: MfaFactorStore) => Promise<void>) =>
		contractCase(input, name, body);
	return [
		test("lists nothing for a subject with no factor", async (store) => {
			assert.deepStrictEqual(await store.list("nobody"), []);
		}),

		test(
			"returns a created record whole, as plain data, its undefined fields named",
			async (store) => {
				// Strictly: a key too many, one left out, or a class instance in place
				// of plain data fails here.
				const full = RECORD();
				const bare = RECORD({
					id: FACTOR_2,
					label: undefined,
					binding: undefined,
					lastUsedAt: undefined,
				});
				await store.create(full);
				await store.create(bare);
				assert.deepStrictEqual(byId(await store.list("user-1")), [full, bare]);
			},
		),

		test("keeps data verbatim: the store never reads it", async (store) => {
			const samples = ["[]", "{}", '{"a":[],"b":{}}', "ü∆ 漢字 🙂", "x".repeat(4096)];
			for (const [i, data] of samples.entries()) {
				await store.create(RECORD({ id: factorId(`factor-${i}`), data }));
			}
			const listed = byId(await store.list("user-1"));
			assert.deepStrictEqual(
				listed.map((r) => r.data),
				samples,
			);
		}),

		test("round-trips every binding and any kind", async (store) => {
			const records = [
				RECORD({ id: factorId("a"), kind: "totp", binding: "password" }),
				RECORD({ id: factorId("b"), kind: "email", binding: "email_proof" }),
				RECORD({ id: factorId("c"), kind: "webauthn", binding: "mfa" }),
				RECORD({ id: factorId("d"), kind: "recovery_code", binding: undefined }),
				RECORD({ id: factorId("e"), kind: "acme-contributed", binding: "mfa" }),
			];
			for (const record of records) await store.create(record);
			assert.deepStrictEqual(byId(await store.list("user-1")), records);
		}),

		test("refuses a duplicate (subject, id), and keeps the record as it was", async (store) => {
			await store.create(RECORD());
			await assert.rejects(store.create(RECORD({ data: "v2.other", label: "Other" })));
			assert.deepStrictEqual(await store.list("user-1"), [RECORD()]);
		}),

		test("lets one of N concurrent creates of one (subject, id) through", async (store) => {
			const results = await Promise.allSettled(
				Array.from({ length: 10 }, (_, i) => store.create(RECORD({ data: `v2.${i}` }))),
			);
			assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
			assert.equal((await store.list("user-1")).length, 1);
		}),

		test(
			"keeps subjects apart: the same id under another subject is another record",
			async (store) => {
				const mine = RECORD();
				const theirs = RECORD({ subject: "user-2", data: "v2.theirs" });
				await store.create(mine);
				await store.create(theirs);
				assert.deepStrictEqual(await store.list("user-1"), [mine]);
				assert.deepStrictEqual(await store.list("user-2"), [theirs]);
			},
		),

		test(
			"updates at the current version: data, label and lastUsedAt replaced, version + 1, nothing else moved",
			async (store) => {
				const record = RECORD();
				await store.create(record);
				const next = {
					data: "v2.re-sealed",
					label: "Work phone",
					lastUsedAt: new Date("2026-09-03T00:00:00.000Z"),
				};
				const updated = await store.update("user-1", FACTOR_1, 1, next);
				const expected = { ...record, ...next, version: 2 };
				assert.deepStrictEqual(updated, expected);
				assert.deepStrictEqual(await store.list("user-1"), [expected]);
			},
		),

		test("clears label and lastUsedAt when the update says undefined", async (store) => {
			await store.create(RECORD());
			const updated = await store.update("user-1", FACTOR_1, 1, {
				data: "v2.re-sealed",
				label: undefined,
				lastUsedAt: undefined,
			});
			assert.deepStrictEqual(updated, {
				...RECORD(),
				data: "v2.re-sealed",
				label: undefined,
				lastUsedAt: undefined,
				version: 2,
			});
			assert.deepStrictEqual(await store.list("user-1"), [updated]);
		}),

		test("answers null for a version that moved, and changes nothing", async (store) => {
			await store.create(RECORD());
			const next = { data: "v2.late", label: "Late", lastUsedAt: undefined };
			assert.equal(await store.update("user-1", FACTOR_1, 0, next), null);
			assert.equal(await store.update("user-1", FACTOR_1, 2, next), null);
			assert.deepStrictEqual(await store.list("user-1"), [RECORD()]);
		}),

		test("answers null for a record that is gone, and creates nothing", async (store) => {
			const next = { data: "v2.x", label: undefined, lastUsedAt: undefined };
			assert.equal(await store.update("user-1", FACTOR_1, 1, next), null);
			assert.deepStrictEqual(await store.list("user-1"), []);
		}),

		test(
			"refuses, with a RangeError, an update at Number.MAX_SAFE_INTEGER — the next version would be no safe integer — and changes nothing, whatever the stored version; the update that reaches it passes",
			async (store) => {
				const max = Number.MAX_SAFE_INTEGER;
				await store.create(RECORD({ version: max - 1 }));
				const next = { data: "v2.re-sealed", label: undefined, lastUsedAt: undefined };
				const reached = await store.update("user-1", FACTOR_1, max - 1, next);
				assert.deepStrictEqual(reached, { ...RECORD(), ...next, version: max });
				await assert.rejects(store.update("user-1", FACTOR_1, max, next), RangeError);
				assert.deepStrictEqual(await store.list("user-1"), [reached]);
				await assert.rejects(store.update("user-1", factorId("gone"), max, next), RangeError);
			},
		),

		test("lets exactly one of N concurrent updates at one version win", async (store) => {
			await store.create(RECORD());
			const results = await Promise.all(
				Array.from({ length: 10 }, (_, i) =>
					store.update("user-1", FACTOR_1, 1, {
						data: `v2.writer-${i}`,
						label: `Writer ${i}`,
						lastUsedAt: undefined,
					}),
				),
			);
			const winners = results.filter((r) => r !== null);
			assert.equal(winners.length, 1);
			assert.deepStrictEqual(await store.list("user-1"), winners);
			assert.equal(winners[0]?.version, 2);
		}),

		test("never reaches another subject's record through update", async (store) => {
			await store.create(RECORD({ subject: "user-2" }));
			const next = { data: "v2.forged", label: undefined, lastUsedAt: undefined };
			assert.equal(await store.update("user-1", FACTOR_1, 1, next), null);
			assert.deepStrictEqual(await store.list("user-2"), [RECORD({ subject: "user-2" })]);
			assert.deepStrictEqual(await store.list("user-1"), []);
		}),

		test(
			"removes one record, idempotently, leaving the subject's others and other subjects'",
			async (store) => {
				const a = factorId("a");
				const b = factorId("b");
				await store.create(RECORD({ id: a }));
				await store.create(RECORD({ id: b }));
				await store.create(RECORD({ id: a, subject: "user-2" }));
				await store.remove("user-1", a);
				await store.remove("user-1", a);
				await store.remove("user-1", factorId("never-was"));
				assert.deepStrictEqual(await store.list("user-1"), [RECORD({ id: b })]);
				assert.deepStrictEqual(await store.list("user-2"), [RECORD({ id: a, subject: "user-2" })]);
			},
		),

		test(
			"removes every record of one subject, idempotently, and no other subject's",
			async (store) => {
				await store.create(RECORD({ id: factorId("a") }));
				await store.create(RECORD({ id: factorId("b") }));
				await store.create(RECORD({ id: factorId("c"), subject: "user-2" }));
				await store.removeAllForSubject("user-1");
				await store.removeAllForSubject("user-1");
				await store.removeAllForSubject("nobody");
				assert.deepStrictEqual(await store.list("user-1"), []);
				assert.deepStrictEqual(await store.list("user-2"), [
					RECORD({ id: factorId("c"), subject: "user-2" }),
				]);
			},
		),

		test("takes a record again after it was removed", async (store) => {
			// A removed factor leaves nothing behind that refuses the next one.
			await store.create(RECORD());
			await store.removeAllForSubject("user-1");
			await store.create(RECORD({ data: "v2.again" }));
			assert.deepStrictEqual(await store.list("user-1"), [RECORD({ data: "v2.again" })]);
		}),
	];
}
