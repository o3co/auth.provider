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
 * both. Each case builds its own and closes it. The concurrent cases split
 * their writers across `store` and `second`, a second instance on the same
 * backend, so a Store run on its own backend proves the fence across
 * processes, never by an in-process lock. A store with one instance per
 * process gives no `second`, and proves no fence across processes. The
 * outage case runs only with `supports.unreachable`; without it, one passing
 * case names it as not run.
 *
 * The cases talk only to the port and read every answer with core's
 * readers, so a SQL-backed, a REST-backed and a bundled store run them
 * unchanged. Repetitions catch a race a real backend leaves open only
 * sometimes; they do not prove its isolation. No case can reach a set that
 * exists without a generation — only a writer from before the set members
 * leaves one — so the rule that a conditional write against it answers
 * `conflict` and mints nothing is the Store's own tests' to prove.
 *
 * A write conditional on a read is valid only within the store's
 * write-lifetime bound of that read: the bound runs from the versioned read
 * that produced the write's expected generation to the write's commit or
 * failure, transport and queues included. The port's owning module keeps it;
 * callers outside it never hold a generation. An emptied set's tombstone is
 * kept for at least that bound (`BUNDLED_STORE_WRITE_LIFETIME_MS`, 24 h, for
 * the bundled stores). For MFA, the factor-set writer keeps the bound under
 * its lease (at most 16 × `mfa.storeTimeoutMs`).
 * The tombstone cases run under `forceExpire`; no case can prove the bound
 * itself, which the Store's configuration and the writer's lease keep.
 *
 * STAND-IN: the first group is the set variant of the generic
 * conditional-write suite, which has not landed. When it does, the binding
 * hands the members to it and drops that group; the second group is the
 * factor set's own.
 */

import assert from "node:assert/strict";
import {
	type ConditionalCreateAnswer,
	type ConditionalSetRemoveAnswer,
	isMfaFactorId,
	isStoreGeneration,
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
	forceExpireOf,
	type MfaFactorStoreContractInput,
	type MfaFactorStoreHarness,
	notRunCase,
	rejects,
	unreachableOf,
} from "./factorStore.contract.mjs";

/** How many times a race between two writers is run. */
const ROUNDS = 20;

/** How many writers race in one batch of creates. */
const WRITERS = 10;

/** A factor id as the provider makes one: `name` padded to 22 base64url characters. */
const factorId = (name: string): string => name.padEnd(22, "A");

const FACTOR_A = factorId("set-a");
const FACTOR_B = factorId("set-b");
const FACTOR_X = factorId("set-x");
const FACTOR_Y = factorId("set-y");

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

const byId = (records: readonly MfaFactorRecord[]): MfaFactorRecord[] =>
	[...records].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

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
	for (const member of ["listVersioned", "createIf", "removeIf"] as const) {
		assert.equal(typeof store[member], "function", `the store has no ${member}`);
	}
	return {
		store,
		read: async (subject) => readMfaFactorSet(await store.listVersioned?.(subject), subject),
		createIf: async (record, expected) =>
			readConditionalCreateAnswer(await store.createIf?.(record, expected)),
		removeIf: async (subject, id, expected) =>
			readConditionalSetRemoveAnswer(await store.removeIf?.(subject, id, expected)),
	};
}

/** The case's two instances: `one` the harness's store, `two` its second (the store again without one). */
interface Instances {
	readonly one: SetView;
	readonly two: SetView;
	/** `one` for an even `i`, `two` for an odd one. */
	at(i: number): SetView;
	readonly harness: MfaFactorStoreHarness;
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

/** `record` written by the legacy unconditional `create`, which the set's members replace. */
const createUnconditionally = (view: SetView, record: MfaFactorRecord): Promise<void> =>
	view.store.create(record);

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
	const test = (name: string, body: (instances: Instances) => Promise<void>): ContractCase => ({
		name,
		run: async () => {
			const harness = await input.build();
			try {
				const one = viewOf(harness.store);
				const two = harness.second === undefined ? one : viewOf(harness.second);
				await body({ one, two, at: (i) => (i % 2 === 0 ? one : two), harness });
			} finally {
				await harness.close?.();
			}
		},
	});

	const outageCase =
		test("rejects every set member when it cannot reach its backend, and answers none as an empty set, missing or conflict", async ({
			harness,
		}) => {
			const down = unreachableOf(harness)();
			const generation = "unreachable-g" as StoreGeneration;
			await rejects(async () => down.listVersioned?.("user-1"), "listVersioned");
			await rejects(
				async () => down.createIf?.(RECORD(FACTOR_A, "user-1"), null),
				"createIf at null",
			);
			await rejects(
				async () => down.createIf?.(RECORD(FACTOR_A, "user-1"), generation),
				"createIf",
			);
			await rejects(async () => down.removeIf?.("user-1", FACTOR_A, generation), "removeIf");
		});

	const tombstoneCases: readonly ContractCase[] = [
		// The factor set's own: what a late writer meets within the bound.
		test("a tombstone stands within the write-lifetime bound: a late first binding and a late write at a generation read before it are refused, and write nothing", async ({
			one,
			two,
			harness,
		}) => {
			forceExpireOf(harness);
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

		// STAND-IN until the generic suite's set variant runs its own expiry case
		// under forceExpire; then this one is dropped.
		test("an expired tombstone reads as absent, and a generation seen before it is never issued again", async ({
			one,
			two,
			harness,
		}) => {
			const forceExpire = forceExpireOf(harness);
			const seen = new Set<StoreGeneration>();
			const note = (generation: StoreGeneration | null): void => {
				if (generation !== null) seen.add(generation);
			};
			let generation: StoreGeneration | null = null;
			for (const id of [FACTOR_A, FACTOR_B]) {
				generation = landed(await one.createIf(RECORD(id, "user-1"), generation), "a create");
				note(generation);
			}
			await two.store.removeAllForSubject("user-1");
			note((await one.read("user-1")).generation);
			await forceExpire("user-1");
			assert.deepStrictEqual(await two.read("user-1"), { generation: null, items: [] });
			const again = landed(await one.createIf(RECORD(FACTOR_X, "user-1"), null), "the re-create");
			assert.ok(
				!seen.has(again),
				"a generation seen before the tombstone expired was issued again",
			);
			assert.deepStrictEqual(await two.read("user-1"), {
				generation: again,
				items: [RECORD(FACTOR_X, "user-1")],
			});

			const last = await seed(one, "user-2", [RECORD(FACTOR_A, "user-2")]);
			landed(await two.removeIf("user-2", FACTOR_A, last), "the last removal");
			await forceExpire("user-2");
			assert.deepStrictEqual(await one.read("user-2"), { generation: null, items: [] });

			await one.store.removeAllForSubject("nobody");
			await forceExpire("nobody");
			assert.deepStrictEqual(await two.read("nobody"), { generation: null, items: [] });
		}),

		test("a set holding a record has no expiry: one written after a reset outlives the tombstone", async ({
			one,
			two,
			harness,
		}) => {
			const forceExpire = forceExpireOf(harness);
			await one.store.removeAllForSubject("user-1");
			const tombstone = (await two.read("user-1")).generation;
			const bound = landed(
				await two.createIf(RECORD(FACTOR_A, "user-1"), tombstone),
				"a binding on the tombstone",
			);
			await forceExpire("user-1");
			assert.deepStrictEqual(await one.read("user-1"), {
				generation: bound,
				items: [RECORD(FACTOR_A, "user-1")],
			});
		}),
	];

	return [
		// --- STAND-IN: the generic suite's set variant ---------------------

		test("a set never written answers no generation and no records", async ({ one }) => {
			assert.deepStrictEqual(await one.read("nobody"), { generation: null, items: [] });
		}),

		test("lets exactly one of two concurrent first bindings through, one from each instance", async ({
			one,
			two,
		}) => {
			const records = [RECORD(FACTOR_A, "user-1"), RECORD(FACTOR_B, "user-1")] as const;
			const answers = await Promise.all([
				one.createIf(records[0], null),
				two.createIf(records[1], null),
			]);
			const won = answers.flatMap((answer, i) =>
				answer.outcome === "created" ? [{ answer, record: records[i] }] : [],
			);
			assert.equal(won.length, 1, `${won.length} first bindings landed`);
			assert.deepStrictEqual(await one.read("user-1"), {
				generation: won[0]?.answer.generation,
				items: [won[0]?.record],
			});
		}),

		test("a reset leaves the set at a new generation, so a first binding after it is a conflict", async ({
			one,
			two,
		}) => {
			const before = await seed(one, "user-1", [RECORD(FACTOR_A, "user-1")]);
			await one.store.removeAllForSubject("user-1");
			const after = await two.read("user-1");
			assert.deepStrictEqual(after.items, [], "the reset left records");
			assert.ok(after.generation !== null, "the reset left no generation");
			assert.notEqual(after.generation, before, "the reset kept the generation");
			assert.deepStrictEqual(await two.createIf(RECORD(FACTOR_B, "user-1"), null), {
				outcome: "conflict",
			});
			assert.deepStrictEqual((await one.read("user-1")).items, []);
		}),

		test("an update keeps the set's generation, and a write at it still lands", async ({
			one,
			two,
		}) => {
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

		test("a create at a generation that moved writes no record", async ({ one, two }) => {
			const first = await seed(one, "user-1", [RECORD(FACTOR_A, "user-1")]);
			landed(await two.createIf(RECORD(FACTOR_B, "user-1"), first), "a create at the current one");
			assert.deepStrictEqual(await one.createIf(RECORD(FACTOR_X, "user-1"), first), {
				outcome: "conflict",
			});
			assert.deepStrictEqual(byId((await two.read("user-1")).items), [
				RECORD(FACTOR_A, "user-1"),
				RECORD(FACTOR_B, "user-1"),
			]);
		}),

		test("a create of an id the set holds, at the current generation, is a conflict that changes nothing", async ({
			one,
			two,
		}) => {
			const generation = await seed(one, "user-1", [RECORD(FACTOR_A, "user-1")]);
			const again = RECORD(FACTOR_A, "user-1", { data: "v2.other", label: "Other" });
			assert.deepStrictEqual(await two.createIf(again, generation), { outcome: "conflict" });
			assert.deepStrictEqual(await one.read("user-1"), {
				generation,
				items: [RECORD(FACTOR_A, "user-1")],
			});
		}),

		test("removing the last record keeps the set at a new generation", async ({ one, two }) => {
			const first = await seed(one, "user-1", [RECORD(FACTOR_A, "user-1")]);
			const next = landed(await two.removeIf("user-1", FACTOR_A, first), "the removal");
			assert.notEqual(next, first, "the removal kept the generation");
			assert.deepStrictEqual(await one.read("user-1"), { generation: next, items: [] });
			assert.deepStrictEqual(await one.createIf(RECORD(FACTOR_B, "user-1"), null), {
				outcome: "conflict",
			});
		}),

		// --- The factor set's own cases ------------------------------------

		test("two removals of different records at one generation, one from each instance: one removed, the other a conflict that keeps its record", async ({
			at,
		}) => {
			for (let i = 0; i < ROUNDS; i += 1) {
				const subject = `round-${i}`;
				const records = [RECORD(FACTOR_A, subject), RECORD(FACTOR_B, subject)] as const;
				const generation = await seed(at(0), subject, records);
				const answers = await Promise.all([
					at(i).removeIf(subject, FACTOR_A, generation),
					at(i + 1).removeIf(subject, FACTOR_B, generation),
				]);
				const outcomes = answers.map((answer) => answer.outcome).sort();
				assert.deepStrictEqual(outcomes, ["conflict", "removed"], `round ${i}: ${outcomes}`);
				const won = answers.find((answer) => answer.outcome === "removed");
				const kept = answers[0]?.outcome === "removed" ? records[1] : records[0];
				assert.deepStrictEqual(
					await at(i).read(subject),
					{ generation: won?.outcome === "removed" ? won.generation : null, items: [kept] },
					`round ${i}: the set, at the generation the removal answered`,
				);
			}
		}),

		test("concurrent creates of different records at one generation: exactly one created, the set one larger", async ({
			at,
		}) => {
			const generation = await seed(at(0), "user-1", [RECORD(FACTOR_A, "user-1")]);
			const records = Array.from({ length: WRITERS }, (_, i) =>
				RECORD(factorId(`writer-${i}`), "user-1"),
			);
			const answers = await Promise.all(
				records.map((record, i) => at(i).createIf(record, generation)),
			);
			const won = answers.flatMap((answer, i) =>
				answer.outcome === "created" ? [{ answer, record: records[i] }] : [],
			);
			assert.equal(won.length, 1, `${won.length} creates landed`);
			assert.deepStrictEqual(await at(1).read("user-1"), {
				generation: won[0]?.answer.generation,
				items: byId([RECORD(FACTOR_A, "user-1"), won[0]?.record as MfaFactorRecord]),
			});
		}),

		test("a removal racing a create at one generation: exactly one wins, and the set is the winner's", async ({
			at,
		}) => {
			for (let i = 0; i < ROUNDS; i += 1) {
				const subject = `round-${i}`;
				const generation = await seed(at(0), subject, [RECORD(FACTOR_A, subject)]);
				const removal = () => at(i).removeIf(subject, FACTOR_A, generation);
				const create = () => at(i + 1).createIf(RECORD(FACTOR_B, subject), generation);
				const [removed, created] =
					i % 2 === 0
						? await Promise.all([removal(), create()])
						: await Promise.all([create(), removal()]).then(([c, r]) => [r, c] as const);
				const wins = [removed.outcome === "removed", created.outcome === "created"];
				assert.equal(
					wins.filter(Boolean).length,
					1,
					`round ${i}: ${removed.outcome}, ${created.outcome}`,
				);
				const expected = wins[0] ? [] : [RECORD(FACTOR_A, subject), RECORD(FACTOR_B, subject)];
				const winner = removed.outcome === "removed" ? removed : created;
				const after = await at(i).read(subject);
				assert.deepStrictEqual(byId(after.items), expected, `round ${i}`);
				assert.equal(
					after.generation,
					"generation" in winner ? winner.generation : undefined,
					`round ${i}: the set at another generation than the winner answered`,
				);
			}
		}),

		test("a set taken back to the same records answers conflict at the generation read before it, and no generation repeats", async ({
			one,
			two,
		}) => {
			const read = await seed(one, "user-1", [RECORD(FACTOR_A, "user-1")]);
			const removed = landed(await two.removeIf("user-1", FACTOR_A, read), "the removal");
			const again = landed(
				await one.createIf(RECORD(FACTOR_A, "user-1"), removed),
				"the re-create",
			);
			assert.deepStrictEqual(await two.read("user-1"), {
				generation: again,
				items: [RECORD(FACTOR_A, "user-1")],
			});
			assert.equal(new Set([read, removed, again]).size, 3, "a generation repeated");
			assert.deepStrictEqual(await two.createIf(RECORD(FACTOR_B, "user-1"), read), {
				outcome: "conflict",
			});
			assert.deepStrictEqual(await one.removeIf("user-1", FACTOR_A, read), { outcome: "conflict" });
			assert.deepStrictEqual((await one.read("user-1")).items, [RECORD(FACTOR_A, "user-1")]);
		}),

		test("a reset fences every write read before it, and leaves a set never written at a generation", async ({
			one,
			two,
		}) => {
			const read = await seed(one, "user-1", [RECORD(FACTOR_A, "user-1")]);
			await two.store.removeAllForSubject("user-1");
			assert.deepStrictEqual(await one.createIf(RECORD(FACTOR_B, "user-1"), read), {
				outcome: "conflict",
			});
			assert.deepStrictEqual(await one.removeIf("user-1", FACTOR_A, read), { outcome: "conflict" });
			const reset = await two.read("user-1");
			assert.deepStrictEqual(reset.items, []);

			// A reset of a set already empty — reset before, or emptied by its last
			// removal — moves the generation all the same.
			await one.store.removeAllForSubject("user-1");
			const again = (await two.read("user-1")).generation;
			assert.ok(again !== null && again !== reset.generation, "a second reset kept the generation");
			const emptied = landed(
				await two.removeIf(
					"user-2",
					FACTOR_A,
					await seed(one, "user-2", [RECORD(FACTOR_A, "user-2")]),
				),
				"the last removal",
			);
			await one.store.removeAllForSubject("user-2");
			const resetEmptied = (await two.read("user-2")).generation;
			assert.ok(
				resetEmptied !== null && resetEmptied !== emptied,
				"a reset of an emptied set kept the generation",
			);
			assert.deepStrictEqual(await two.createIf(RECORD(FACTOR_B, "user-2"), emptied), {
				outcome: "conflict",
			});

			await one.store.removeAllForSubject("nobody");
			const tombstone = await two.read("nobody");
			assert.deepStrictEqual(tombstone.items, []);
			assert.ok(tombstone.generation !== null, "a reset of a set never written left none");
			assert.deepStrictEqual(await two.createIf(RECORD(FACTOR_A, "nobody"), null), {
				outcome: "conflict",
			});
		}),

		test("missing writes nothing: the generation stays and a write at it lands; an absent set answers missing to a removal and conflict to a create", async ({
			one,
			two,
		}) => {
			const generation = await seed(one, "user-1", [RECORD(FACTOR_A, "user-1")]);
			assert.deepStrictEqual(await two.removeIf("user-1", FACTOR_X, generation), {
				outcome: "missing",
			});
			assert.equal((await one.read("user-1")).generation, generation, "missing moved it");
			landed(await one.createIf(RECORD(FACTOR_B, "user-1"), generation), "a create after missing");

			assert.deepStrictEqual(await two.removeIf("nobody", FACTOR_A, generation), {
				outcome: "missing",
			});
			assert.deepStrictEqual(await one.createIf(RECORD(FACTOR_A, "nobody"), generation), {
				outcome: "conflict",
			});
			assert.deepStrictEqual(await two.read("nobody"), { generation: null, items: [] });
		}),

		test("a snapshot read beside a create is one snapshot: without the record its generation is fenced, with it the create's generation", async ({
			at,
		}) => {
			for (let i = 0; i < ROUNDS; i += 1) {
				const subject = `round-${i}`;
				const generation = await seed(at(0), subject, [RECORD(FACTOR_A, subject)]);
				const read = () => at(i).read(subject);
				const create = () => at(i + 1).createIf(RECORD(FACTOR_X, subject), generation);
				// Both awaited: the create has committed before anything below writes.
				const [snapshot, created] =
					i % 2 === 0
						? await Promise.all([read(), create()])
						: await Promise.all([create(), read()]).then(([c, s]) => [s, c] as const);
				const createdAt = landed(created, `round ${i}: the create`);
				if (snapshot.items.some((record) => record.id === FACTOR_X)) {
					assert.equal(
						snapshot.generation,
						createdAt,
						`round ${i}: the record at another generation`,
					);
				} else {
					assert.deepStrictEqual(snapshot.items, [RECORD(FACTOR_A, subject)], `round ${i}`);
					assert.ok(snapshot.generation !== null, `round ${i}: no generation`);
					assert.deepStrictEqual(
						await at(i).createIf(RECORD(FACTOR_Y, subject), snapshot.generation),
						{ outcome: "conflict" },
						`round ${i}: a write at the snapshot without the record landed`,
					);
				}
			}
		}),

		test("list and listVersioned answer the same records, and nothing else as a record", async ({
			one,
			two,
		}) => {
			const records = [
				RECORD(FACTOR_A, "user-1"),
				RECORD(FACTOR_B, "user-1", { label: undefined, binding: undefined, lastUsedAt: undefined }),
			];
			await seed(one, "user-1", records);
			const versioned = await two.read("user-1");
			assert.deepStrictEqual(byId(versioned.items), records);
			assert.deepStrictEqual(byId(await two.store.list("user-1")), records);
			for (const item of versioned.items) {
				assert.ok(isMfaFactorId(item.id), `${item.id} is no factor id`);
			}
		}),

		test("each unconditional write, create and remove, moves the generation", async ({
			one,
			two,
		}) => {
			await createUnconditionally(one, RECORD(FACTOR_A, "user-1"));
			const created = (await two.read("user-1")).generation;
			assert.ok(created !== null, "a create left no generation");
			assert.deepStrictEqual(await two.createIf(RECORD(FACTOR_X, "user-1"), null), {
				outcome: "conflict",
			});

			await createUnconditionally(two, RECORD(FACTOR_B, "user-1"));
			const again = (await one.read("user-1")).generation;
			assert.ok(again !== null && again !== created, "a create kept the generation");
			assert.deepStrictEqual(await one.createIf(RECORD(FACTOR_X, "user-1"), created), {
				outcome: "conflict",
			});

			await one.store.remove("user-1", FACTOR_A);
			const removed = (await two.read("user-1")).generation;
			assert.ok(removed !== null && removed !== again, "a remove kept the generation");
			assert.deepStrictEqual(await two.removeIf("user-1", FACTOR_B, again), {
				outcome: "conflict",
			});

			await two.store.remove("user-1", FACTOR_B);
			const emptied = await one.read("user-1");
			assert.deepStrictEqual(emptied.items, []);
			assert.ok(
				emptied.generation !== null && emptied.generation !== removed,
				"the last remove kept it",
			);
		}),

		test("every answer is one core's readers read, and every generation a store generation", async ({
			one,
		}) => {
			const { store } = one;
			const raw: unknown[] = [];
			const keep = <T,>(answer: T): T => {
				raw.push(answer);
				return answer;
			};
			const empty = readMfaFactorSet(keep(await store.listVersioned?.("user-1")), "user-1");
			assert.equal(empty.generation, null);
			const created = readConditionalCreateAnswer(
				keep(await store.createIf?.(RECORD(FACTOR_A, "user-1"), null)),
			);
			const generation = landed(created, "the create");
			readConditionalCreateAnswer(keep(await store.createIf?.(RECORD(FACTOR_A, "user-1"), null)));
			readConditionalSetRemoveAnswer(keep(await store.removeIf?.("user-1", FACTOR_X, generation)));
			const removed = readConditionalSetRemoveAnswer(
				keep(await store.removeIf?.("user-1", FACTOR_A, generation)),
			);
			readConditionalSetRemoveAnswer(keep(await store.removeIf?.("user-1", FACTOR_A, generation)));
			const listed = readMfaFactorSet(keep(await store.listVersioned?.("user-1")), "user-1");
			for (const seen of [generation, landed(removed, "the removal"), listed.generation]) {
				assert.ok(isStoreGeneration(seen), `${String(seen)} is no store generation`);
			}
			assert.equal(raw.length, 7);
		}),

		...(input.supports?.unreachable === true ? [outageCase] : []),
		...(input.supports?.forceExpire === true ? tombstoneCases : []),
		...notRunCase([
			...(input.supports?.unreachable === true
				? []
				: ["the outage case (unreachable not declared)"]),
			...(input.supports?.forceExpire === true
				? []
				: ["the tombstone cases (forceExpire not declared)"]),
		]),
	];
}
