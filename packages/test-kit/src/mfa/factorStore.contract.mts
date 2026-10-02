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
 * adapter. "Only a subject with no record that may count opens a first
 * binding" (the same ADR's F3) is only as strong as the store: a record that comes back without a field, a
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
 * version; a successful update reaching no other record — the same id under
 * another subject, the subject's other factors; removal of one record, once,
 * and of a subject's records, idempotently, and no further; and a removed
 * record taken again; and, with `unreachable`, every member rejecting out of
 * reach. Every record id is 22 base64url characters, as the provider makes
 * one. Each case builds a fresh harness and closes it; the concurrent ones
 * split their writers across `store` and `second`.
 *
 * Records are written and removed through the factor set's conditional
 * members, at the generation the set is at. Each answer is read with core's
 * readers.
 *
 * The harness is the factor set's binding's too
 * (`mfaFactorStoreConditionalContract`): one `build` serves both suites.
 */

import assert from "node:assert/strict";
import {
	type ConditionalCreateAnswer,
	type ConditionalSetRemoveAnswer,
	type MfaFactorRecord,
	type MfaFactorStore,
	newStoreGeneration,
	readConditionalCreateAnswer,
	readConditionalSetRemoveAnswer,
	readMfaFactorSet,
	type StoreGeneration,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "@o3co/auth-provider-core/testing";

/** What one case runs over: a fresh, empty store, and what else the backend gives. */
export interface MfaFactorStoreHarness {
	/** The store under test, holding nothing. */
	readonly store: MfaFactorStore;
	/**
	 * The same backend through a second instance: another connection, pool or
	 * adapter. Absent: `store` again, which is right for an in-process store
	 * and gives no cross-process proof.
	 */
	readonly second?: MfaFactorStore;
	/** A store over the same backend that cannot reach it. Needs `supports.unreachable`. */
	readonly unreachable?: () => MfaFactorStore;
	/**
	 * Moves the backend's clock past any retention deadline the store set
	 * (`subject` names the set the case expires). It never judges membership,
	 * and never deletes: that an emptied set's tombstone expires and a set
	 * holding a record does not is the store's own doing. Needs
	 * `supports.forceExpire`; only the factor set's binding uses it.
	 */
	readonly forceExpire?: (subject: string) => Promise<void>;
	/** Releases what the store runs on once the case ends. */
	readonly close?: () => Promise<void>;
}

export interface MfaFactorStoreContractInput {
	/** Builds a fresh harness for each case. */
	readonly build: () => Promise<MfaFactorStoreHarness>;
	/**
	 * The hooks every harness `build` answers, declared up front so the case
	 * list is fixed when the suite is built. A declared hook a harness lacks
	 * fails its case; an undeclared one runs no case, and one passing case
	 * names what did not run.
	 */
	readonly supports?: { readonly unreachable?: boolean; readonly forceExpire?: boolean };
}

/** One passing case that names what did not run, or none when everything ran. */
export function notRunCase(left: readonly string[]): ContractCase[] {
	return left.length === 0 ? [] : [{ name: `not run: ${left.join("; ")}`, run: async () => {} }];
}

/** `harness.unreachable`, bound to the harness, or the case's failure when a harness that declared it lacks it. */
export function unreachableOf(harness: MfaFactorStoreHarness): () => MfaFactorStore {
	const unreachable = harness.unreachable?.bind(harness);
	assert.ok(
		unreachable !== undefined,
		"supports.unreachable is declared, and the harness gives no unreachable",
	);
	return unreachable;
}

/** Whether `run` rejects; `what` names it in the failure. */
export async function rejects(run: () => Promise<unknown>, what: string): Promise<void> {
	let answered: unknown;
	try {
		answered = await run();
	} catch {
		return;
	}
	assert.fail(`${what} answered ${JSON.stringify(answered)} out of reach, rather than rejecting`);
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

/** A record with none of the optional fields. */
const BARE = {
	id: FACTOR_2,
	label: undefined,
	binding: undefined,
	lastUsedAt: undefined,
} as const;

const byId = (records: readonly MfaFactorRecord[]): MfaFactorRecord[] =>
	[...records].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

/** The generation `subject`'s set is at: `null` for a set never written. */
async function generationOf(
	store: MfaFactorStore,
	subject: string,
): Promise<StoreGeneration | null> {
	return readMfaFactorSet(await store.listVersioned(subject), subject).generation;
}

/** `record` created in its subject's set at the generation the set is then at, read as core reads it. */
async function createAtCurrent(
	store: MfaFactorStore,
	record: MfaFactorRecord,
): Promise<ConditionalCreateAnswer> {
	return readConditionalCreateAnswer(
		await store.createIf(record, await generationOf(store, record.subject)),
	);
}

/** `records` created one after another, each in its subject's set at the generation it is then at. */
async function seed(store: MfaFactorStore, ...records: readonly MfaFactorRecord[]): Promise<void> {
	for (const record of records) {
		const answer = await createAtCurrent(store, record);
		assert.equal(answer.outcome, "created", `seeding ${record.id} of ${record.subject}`);
	}
}

/** `(subject, id)` removed at the generation the set is then at, read as core reads it. */
async function removeAtCurrent(
	store: MfaFactorStore,
	subject: string,
	id: string,
): Promise<ConditionalSetRemoveAnswer> {
	const generation = await generationOf(store, subject);
	if (generation === null) {
		assert.fail(`${subject}'s set is absent: no removal to ask the store for`);
	}
	return readConditionalSetRemoveAnswer(await store.removeIf(subject, id, generation));
}

/** A case that builds its harness, runs `body` over its store and closes it. */
function contractCase(
	input: MfaFactorStoreContractInput,
	name: string,
	body: (store: MfaFactorStore, harness: MfaFactorStoreHarness) => Promise<void>,
): ContractCase {
	return {
		name,
		run: async () => {
			const harness = await input.build();
			try {
				await body(harness.store, harness);
			} finally {
				await harness.close?.();
			}
		},
	};
}

/** `store` for an even `i`, the harness's second instance for an odd one. */
const nth = (harness: MfaFactorStoreHarness, i: number): MfaFactorStore =>
	i % 2 === 0 ? harness.store : (harness.second ?? harness.store);

/** The cases of the factor store's contract over the harnesses `input` builds. */
export function mfaFactorStoreContract(
	input: MfaFactorStoreContractInput,
): readonly ContractCase[] {
	const test = (
		name: string,
		body: (store: MfaFactorStore, harness: MfaFactorStoreHarness) => Promise<void>,
	) => contractCase(input, name, body);
	return [
		test("lists nothing for a subject with no factor", async (store) => {
			assert.deepStrictEqual(await store.list("nobody"), []);
		}),

		test("returns a created record whole, as plain data, its undefined fields named", async (store) => {
			// Strictly: a key too many, one left out, or a class instance in place
			// of plain data fails here.
			await seed(store, RECORD(), RECORD(BARE));
			assert.deepStrictEqual(byId(await store.list("user-1")), [RECORD(), RECORD(BARE)]);
		}),

		test("keeps data verbatim: the store never reads it", async (store) => {
			const samples = ["[]", "{}", '{"a":[],"b":{}}', "ü∆ 漢字 🙂", "x".repeat(4096)];
			for (const [i, data] of samples.entries()) {
				await seed(store, RECORD({ id: factorId(`factor-${i}`), data }));
			}
			const listed = byId(await store.list("user-1"));
			assert.deepStrictEqual(
				listed.map((r) => r.data),
				samples,
			);
		}),

		test("round-trips every binding and any kind", async (store) => {
			// One record for each binding the record declares: a value added there
			// and not here does not compile.
			const bound = {
				password: RECORD({ id: factorId("a"), kind: "totp", binding: "password" }),
				email_proof: RECORD({ id: factorId("b"), kind: "email", binding: "email_proof" }),
				mfa: RECORD({ id: factorId("c"), kind: "webauthn", binding: "mfa" }),
				federated: RECORD({ id: factorId("f"), kind: "webauthn", binding: "federated" }),
			} satisfies Record<NonNullable<MfaFactorRecord["binding"]>, MfaFactorRecord>;
			const records = byId([
				...Object.values(bound),
				RECORD({ id: factorId("d"), kind: "recovery_code", binding: undefined }),
				RECORD({ id: factorId("e"), kind: "acme-contributed", binding: "mfa" }),
			]);
			await seed(store, ...records);
			assert.deepStrictEqual(byId(await store.list("user-1")), records);
		}),

		test("refuses a duplicate (subject, id) at the current generation, and keeps the record as it was", async (store) => {
			await seed(store, RECORD());
			assert.deepStrictEqual(
				await createAtCurrent(store, RECORD({ data: "v2.other", label: "Other" })),
				{ outcome: "conflict" },
			);
			assert.deepStrictEqual(await store.list("user-1"), [RECORD()]);
		}),

		test("lets one of N concurrent creates of one (subject, id) at one generation through", async (store, harness) => {
			const answers = await Promise.all(
				Array.from({ length: 10 }, async (_, i) =>
					readConditionalCreateAnswer(
						await nth(harness, i).createIf(RECORD({ data: `v2.${i}` }), null),
					),
				),
			);
			assert.equal(answers.filter((answer) => answer.outcome === "created").length, 1);
			assert.equal((await store.list("user-1")).length, 1);
		}),

		test("keeps subjects apart: the same id under another subject is another record", async (store) => {
			const theirs = { subject: "user-2", data: "v2.theirs" };
			await seed(store, RECORD(), RECORD(theirs));
			assert.deepStrictEqual(await store.list("user-1"), [RECORD()]);
			assert.deepStrictEqual(await store.list("user-2"), [RECORD(theirs)]);
		}),

		test("updates at the current version: data, label and lastUsedAt replaced, version + 1, nothing else moved", async (store) => {
			await seed(store, RECORD());
			const next = {
				data: "v2.re-sealed",
				label: "Work phone",
				lastUsedAt: new Date("2026-09-03T00:00:00.000Z"),
			};
			const updated = await store.update("user-1", FACTOR_1, 1, next);
			const expected = { ...RECORD(), ...next, version: 2 };
			assert.deepStrictEqual(updated, expected);
			assert.deepStrictEqual(await store.list("user-1"), [expected]);
		}),

		test("clears label and lastUsedAt when the update says undefined", async (store) => {
			await seed(store, RECORD());
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
			await seed(store, RECORD());
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

		test("refuses, with a RangeError, an update at Number.MAX_SAFE_INTEGER — the next version would be no safe integer — and changes nothing, whatever the stored version; the update that reaches it passes", async (store) => {
			const max = Number.MAX_SAFE_INTEGER;
			await seed(store, RECORD({ version: max - 1 }));
			const next = { data: "v2.re-sealed", label: undefined, lastUsedAt: undefined };
			const reached = await store.update("user-1", FACTOR_1, max - 1, next);
			assert.deepStrictEqual(reached, { ...RECORD(), ...next, version: max });
			await assert.rejects(store.update("user-1", FACTOR_1, max, next), RangeError);
			assert.deepStrictEqual(await store.list("user-1"), [reached]);
			await assert.rejects(store.update("user-1", factorId("gone"), max, next), RangeError);
		}),

		test("lets exactly one of N concurrent updates at one version win", async (store, harness) => {
			await seed(store, RECORD());
			const results = await Promise.all(
				Array.from({ length: 10 }, (_, i) =>
					nth(harness, i).update("user-1", FACTOR_1, 1, {
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

		test("a successful update writes its own record alone: the same id under another subject, and the subject's other factors, stay as they were", async (store) => {
			const sibling = { id: FACTOR_2, data: "v2.sibling" };
			const theirs = { subject: "user-2", data: "v2.theirs" };
			await seed(store, RECORD(), RECORD(sibling), RECORD(theirs));
			const next = { data: "v2.re-sealed", label: "Work phone", lastUsedAt: undefined };
			const updated = await store.update("user-1", FACTOR_1, 1, next);
			assert.deepStrictEqual(updated, { ...RECORD(), ...next, version: 2 });
			assert.deepStrictEqual(byId(await store.list("user-1")), [updated, RECORD(sibling)]);
			assert.deepStrictEqual(await store.list("user-2"), [RECORD(theirs)]);
		}),

		test("never reaches another subject's record through update", async (store) => {
			await seed(store, RECORD({ subject: "user-2" }));
			const next = { data: "v2.forged", label: undefined, lastUsedAt: undefined };
			assert.equal(await store.update("user-1", FACTOR_1, 1, next), null);
			assert.deepStrictEqual(await store.list("user-2"), [RECORD({ subject: "user-2" })]);
			assert.deepStrictEqual(await store.list("user-1"), []);
		}),

		test("removes one record at the current generation, once — again, or one never held, answers missing — leaving the subject's others and other subjects'", async (store) => {
			const a = factorId("a");
			const b = factorId("b");
			await seed(store, RECORD({ id: a }), RECORD({ id: b }), RECORD({ id: a, subject: "user-2" }));
			assert.equal((await removeAtCurrent(store, "user-1", a)).outcome, "removed");
			assert.deepStrictEqual(await removeAtCurrent(store, "user-1", a), { outcome: "missing" });
			assert.deepStrictEqual(await removeAtCurrent(store, "user-1", factorId("never-was")), {
				outcome: "missing",
			});
			assert.deepStrictEqual(await store.list("user-1"), [RECORD({ id: b })]);
			assert.deepStrictEqual(await store.list("user-2"), [RECORD({ id: a, subject: "user-2" })]);
		}),

		test("removes every record of one subject, idempotently, and no other subject's", async (store) => {
			await seed(
				store,
				RECORD({ id: factorId("a") }),
				RECORD({ id: factorId("b") }),
				RECORD({ id: factorId("c"), subject: "user-2" }),
			);
			await store.removeAllForSubject("user-1");
			await store.removeAllForSubject("user-1");
			await store.removeAllForSubject("nobody");
			assert.deepStrictEqual(await store.list("user-1"), []);
			assert.deepStrictEqual(await store.list("user-2"), [
				RECORD({ id: factorId("c"), subject: "user-2" }),
			]);
		}),

		test("takes a record again after it was removed", async (store) => {
			// A removed factor leaves nothing behind that refuses the next one.
			await seed(store, RECORD());
			await store.removeAllForSubject("user-1");
			await seed(store, RECORD({ data: "v2.again" }));
			assert.deepStrictEqual(await store.list("user-1"), [RECORD({ data: "v2.again" })]);
		}),

		...(input.supports?.unreachable === true
			? [
					test("rejects every member when it cannot reach its backend, and answers none as no factors, null or done", async (_store, harness) => {
						const down = unreachableOf(harness)();
						await rejects(() => down.list("user-1"), "list");
						await rejects(() => down.listVersioned("user-1"), "listVersioned");
						await rejects(() => down.createIf(RECORD(), null), "createIf");
						await rejects(
							() =>
								down.update("user-1", FACTOR_1, 1, {
									data: "v2.x",
									label: undefined,
									lastUsedAt: undefined,
								}),
							"update",
						);
						await rejects(
							() => down.removeIf("user-1", FACTOR_1, newStoreGeneration()),
							"removeIf",
						);
						await rejects(() => down.removeAllForSubject("user-1"), "removeAllForSubject");
					}),
				]
			: notRunCase(["the outage case (unreachable not declared)"])),
	];
}
