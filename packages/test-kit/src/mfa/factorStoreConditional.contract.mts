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
 * `MfaFactorStore`'s binding of the conditional-write contract: the cases
 * that hold a store's factor set to its store generation, for every adapter.
 * Only a write the store itself checks fences a concurrent one, so a set
 * whose fence leaks lets two removals both pass the last-factor check, two
 * first bindings both land, or a write read before a reset land after it.
 *
 * It takes the harness `mfaFactorStoreContract` takes: one `build` serves
 * both. It maps the store onto `conditionalSetContract`'s target and runs
 * that suite, so the factor set is held to every rule of a set the suite
 * holds: a subject is the scope, a record the item, `removeAllForSubject`
 * the reset, `update` the member's own update, `create`, `remove` and
 * `removeAllForSubject` the unconditional membership writes. Every listing is
 * read with `readMfaFactorSet`, so a record that is not a whole record of its
 * subject, or an id listed twice, fails the case that read it. `second`,
 * `forceExpire`, `unreachable` and `close` pass through, and the harness's
 * `supports` is the suite's; the port has `list`, `update` and its
 * unconditional writes, so their cases always run.
 *
 * Beside the suite, the factor set's own cases: an update keeps the
 * generation and a write at it lands, and a tombstone refuses a late first
 * binding as well as a late write read before the reset.
 *
 * The cases talk only to the port and read every answer with core's
 * readers, so a SQL-backed, a REST-backed and a bundled store run them
 * unchanged. No case can reach a set that exists without a generation —
 * only a writer from before the set members leaves one — so the rule that a
 * conditional write against it answers `conflict` and mints nothing is the
 * Store's own tests' to prove, as is everything else the suite names it
 * cannot see.
 *
 * The rules are core's conditional-write convention for a set
 * (docs/adapter-surface.md, "Conditional writes"); `MfaFactorStore` says what
 * they mean for the factor set, the write-lifetime bound among them, which
 * no case can prove: the adapter's write lifetime and the writer's lease
 * keep it.
 */

import assert from "node:assert/strict";
import {
	type ConditionalCreateAnswer,
	type ConditionalSetRemoveAnswer,
	type MfaFactorRecord,
	type MfaFactorStore,
	readConditionalCreateAnswer,
	readConditionalSetRemoveAnswer,
	readMfaFactorSet,
	type StoreGeneration,
	type VersionedSet,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "@o3co/auth-provider-core/testing";
import {
	type ConditionalSetHarness,
	type ConditionalSetTarget,
	conditionalSetContract,
} from "../conditionalWrite/conditionalWrite.contract.mjs";
import type {
	MfaFactorStoreContractInput,
	MfaFactorStoreHarness,
} from "./factorStore.contract.mjs";

/** A factor id as the provider makes one: `name` padded to 22 base64url characters. */
const factorId = (name: string): string => name.padEnd(22, "A");

const FACTOR_A = factorId("set-a");
const FACTOR_B = factorId("set-b");

const RECORD = (
	id: string,
	subject: string,
	overrides: Partial<MfaFactorRecord> = {},
): MfaFactorRecord => ({
	id,
	subject,
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: undefined,
	version: 1,
	data: `v2.${id}`,
	...overrides,
});

/** `n` records of `subject`, the same on every call. */
const recordsOf = (subject: string, n: number): readonly MfaFactorRecord[] =>
	Array.from({ length: n }, (_, i) =>
		RECORD(factorId(`member-${i}`), subject, {
			label: i % 2 === 0 ? `Factor ${i}` : undefined,
			lastUsedAt: i % 2 === 0 ? undefined : new Date("2026-09-02T00:00:00.000Z"),
		}),
	);

type Writable<T> = { -readonly [K in keyof T]: T[K] };

/** Changes every mutable part of `record` but its id and subject; a frozen record's own fields are left. */
function mutate(record: MfaFactorRecord): void {
	record.createdAt.setTime(0);
	record.lastUsedAt?.setTime(0);
	if (Object.isFrozen(record)) return;
	const writable = record as Writable<MfaFactorRecord>;
	writable.kind = "mutated";
	writable.label = "Mutated";
	writable.binding = "mfa";
	writable.version += 1;
	writable.data = "v2.mutated";
}

type SetMember = "listVersioned" | "createIf" | "removeIf";

/** The store's set member `name`; the case fails for a store without it. */
function memberOf<K extends SetMember>(
	store: MfaFactorStore,
	name: K,
): NonNullable<MfaFactorStore[K]> {
	const member = store[name];
	assert.ok(typeof member === "function", `the store has no ${name}`);
	return (member as (...args: never[]) => unknown).bind(store) as NonNullable<MfaFactorStore[K]>;
}

/** `store` as the generic suite's target: each member a call of the port, every listing read by `readMfaFactorSet`. */
function targetOf(store: MfaFactorStore): ConditionalSetTarget<MfaFactorRecord> {
	return {
		listVersioned: async (subject) =>
			readMfaFactorSet(await memberOf(store, "listVersioned")(subject), subject),
		list: (subject) => store.list(subject),
		createIf: async (record, expected) => memberOf(store, "createIf")(record, expected),
		removeIf: async (subject, id, expected) => memberOf(store, "removeIf")(subject, id, expected),
		reset: (subject) => store.removeAllForSubject(subject),
		updateMember: async (subject, id) => {
			const current = (await store.list(subject)).find((record) => record.id === id);
			assert.ok(current !== undefined, `${id} is not listed`);
			const updated = await store.update(subject, id, current.version, {
				data: `${current.data}.next`,
				label: "Updated",
				lastUsedAt: new Date("2026-09-03T00:00:00.000Z"),
			});
			assert.ok(updated !== null, "the update did not land");
		},
		unconditional: {
			create: (record) => store.create(record),
			remove: (record) => store.remove(record.subject, record.id),
			removeAllForSubject: (record) => store.removeAllForSubject(record.subject),
		},
	};
}

/** The generic suite's harness over `harness`: its stores as targets, its hooks as they are. */
function setHarnessOf(harness: MfaFactorStoreHarness): ConditionalSetHarness<MfaFactorRecord> {
	const { second, unreachable, forceExpire, close } = harness;
	return {
		store: targetOf(harness.store),
		...(second === undefined ? {} : { second: targetOf(second) }),
		...(unreachable === undefined ? {} : { unreachable: () => targetOf(unreachable()) }),
		...(forceExpire === undefined ? {} : { forceExpire }),
		...(close === undefined ? {} : { close }),
	};
}

/** A store's set members, every answer read by core's readers; the store itself for the rest. */
interface SetView {
	readonly store: MfaFactorStore;
	read(subject: string): Promise<VersionedSet<MfaFactorRecord>>;
	createIf(
		record: MfaFactorRecord,
		expected: StoreGeneration | null,
	): Promise<ConditionalCreateAnswer>;
	removeIf(
		subject: string,
		id: string,
		expected: StoreGeneration,
	): Promise<ConditionalSetRemoveAnswer>;
}

function viewOf(store: MfaFactorStore): SetView {
	const target = targetOf(store);
	return {
		store,
		read: (subject) => target.listVersioned(subject),
		createIf: async (record, expected) =>
			readConditionalCreateAnswer(await target.createIf(record, expected)),
		removeIf: async (subject, id, expected) =>
			readConditionalSetRemoveAnswer(await target.removeIf(subject, id, expected)),
	};
}

/** The generation of a write that had to land. */
function landed(
	answer: { readonly outcome: string; readonly generation?: StoreGeneration },
	what: string,
): StoreGeneration {
	assert.ok(
		(answer.outcome === "created" || answer.outcome === "removed") &&
			answer.generation !== undefined,
		`${what} answered ${answer.outcome}`,
	);
	return answer.generation;
}

/** `records` created one after another into `subject`'s set, from the generation it is at; the last generation. */
async function seed(
	view: SetView,
	subject: string,
	records: readonly MfaFactorRecord[],
): Promise<StoreGeneration> {
	let generation = (await view.read(subject)).generation;
	for (const record of records) {
		generation = landed(await view.createIf(record, generation), "a seeding create");
	}
	assert.ok(generation !== null, "seeding wrote nothing");
	return generation;
}

/** The cases of the factor set's conditional writes over the harnesses `input` builds. */
export function mfaFactorStoreConditionalContract(
	input: MfaFactorStoreContractInput,
): readonly ContractCase[] {
	const test = (
		name: string,
		body: (one: SetView, two: SetView) => Promise<void>,
	): ContractCase => ({
		name,
		run: async () => {
			const harness = await input.build();
			try {
				const one = viewOf(harness.store);
				await body(one, harness.second === undefined ? one : viewOf(harness.second));
			} finally {
				await harness.close?.();
			}
		},
	});

	return [
		...conditionalSetContract<MfaFactorRecord>({
			build: async () => setHarnessOf(await input.build()),
			items: recordsOf,
			idOf: (record) => record.id,
			scopeOf: (record) => record.subject,
			mutate,
			supports: {
				...input.supports,
				updateMember: true,
				list: true,
				unconditional: true,
			},
		}),

		test("an update keeps the set's generation, and a write at it still lands", async (one, two) => {
			const generation = await seed(one, "user-1", [RECORD(FACTOR_A, "user-1")]);
			const updated = await one.store.update("user-1", FACTOR_A, 1, {
				data: "v2.next",
				label: undefined,
				lastUsedAt: new Date("2026-09-03T00:00:00.000Z"),
			});
			assert.equal(updated?.version, 2, "the update did not land");
			assert.equal((await two.read("user-1")).generation, generation, "the update moved it");
			landed(
				await two.createIf(RECORD(FACTOR_B, "user-1"), generation),
				"a create after the update",
			);
		}),

		test("a tombstone stands: a late first binding and a late write at a generation read before the reset are refused, and write nothing", async (one, two) => {
			const read = await seed(one, "user-1", [RECORD(FACTOR_A, "user-1")]);
			await two.store.removeAllForSubject("user-1");
			const tombstone = await one.read("user-1");
			assert.ok(tombstone.generation !== null, "the reset left no tombstone");
			assert.deepStrictEqual(await two.createIf(RECORD(FACTOR_B, "user-1"), null), {
				outcome: "conflict",
			});
			assert.deepStrictEqual(await one.createIf(RECORD(FACTOR_B, "user-1"), read), {
				outcome: "conflict",
			});
			assert.deepStrictEqual(await two.removeIf("user-1", FACTOR_A, read), {
				outcome: "conflict",
			});
			assert.deepStrictEqual(await one.read("user-1"), tombstone);
		}),
	];
}
