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
 * The generic suites of core's conditional-write convention (the rules in
 * docs/adapter-surface.md, "Conditional writes"): `conditionalRecordContract`
 * for a port whose generation guards one record, `conditionalSetContract`
 * for one whose generation guards a set's membership. A port's binding maps
 * its members onto a target; each suite answers its cases, run with any
 * runner's `it`.
 *
 * A record store is held to: `null` for a key never written; a value read
 * back whole with its generation; a replace or removal applied only at the
 * current generation, never creating a record; a new generation on every
 * write, a byte-identical one and a re-create included, and on every
 * unconditional write; one winner among concurrent writes at one generation,
 * through two instances of the store, and an unconditional write serialised
 * with a conditional one; a versioned read from one snapshot; `missing` and
 * `conflict` writing nothing; an expired record read as gone; an outage
 * rejected, never answered as `missing`; answers core's readers accept; and
 * the store's own copy of a value.
 *
 * A set store is held to: `null` for a set never written; one winner among
 * concurrent membership writes at one generation, answering the generation
 * the set is then read at, and a reset serialised with them; a reset that
 * leaves the set at a new generation, created when absent; a member's own
 * update keeping the set's generation; an emptied set kept, at a new
 * generation, until its tombstone expires, a removal's or a reset's, of a
 * set written or never written, and a set holding a member never expiring,
 * one revived from its tombstone included; a set created again after that at
 * a generation never seen before; a held id refused as `conflict`; no
 * generation repeated (ABA); a versioned read from one snapshot; `missing`
 * and `conflict` writing nothing; an outage rejected; answers core's readers
 * accept; and the store's own copy of a member.
 *
 * `forceExpire` moves the backend's clock past any retention deadline the
 * store set. It never judges membership or deletes: what then reads as
 * expired, and what does not, is the store's own doing.
 *
 * A hook a harness may lack is declared in `supports`, so the case list is
 * fixed when the suite is built: an undeclared hook's cases are left out,
 * and one passing case names what was not run; a hook declared and missing
 * fails its case. Each case builds a fresh harness, works on keys or scopes
 * of its own, and closes it.
 */

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
	type ConditionalCreateAnswer,
	type ConditionalRemoveAnswer,
	type ConditionalReplaceAnswer,
	type ConditionalSetRemoveAnswer,
	readConditionalCreateAnswer,
	readConditionalRemoveAnswer,
	readConditionalReplaceAnswer,
	readConditionalSetRemoveAnswer,
	readVersioned,
	readVersionedSet,
	type StoreGeneration,
	type Versioned,
	type VersionedSet,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";

// ---------------------------------------------------------------------------
// Record scope
// ---------------------------------------------------------------------------

/** One key's record-scoped conditional members, as a port exposes them. */
export interface ConditionalRecordTarget<V> {
	/** The port's create path: writes the record, live or not, at a new generation. */
	put(key: string, value: V): Promise<void>;
	getVersioned(key: string): Promise<Versioned<V> | null>;
	replaceIf(key: string, expected: StoreGeneration, value: V): Promise<ConditionalReplaceAnswer>;
	removeIf(key: string, expected: StoreGeneration): Promise<ConditionalRemoveAnswer>;
	/**
	 * The port's unconditional writes of one key, by name. Each writes the value
	 * it is given at a new generation, or, named in the input's `removals`,
	 * removes the key.
	 */
	readonly unconditional: Readonly<Record<string, (key: string, value: V) => Promise<void>>>;
}

/** What one case runs over. */
export interface ConditionalRecordHarness<V> {
	readonly store: ConditionalRecordTarget<V>;
	/**
	 * The same backend through a second instance: another connection, pool or
	 * client. Absent: `store` again. That is right for an in-process store,
	 * and gives no cross-process proof.
	 */
	readonly second?: ConditionalRecordTarget<V>;
	/**
	 * Moves the backend's clock past any retention deadline the store set
	 * (`key` names the record the case expires). It never judges what expires,
	 * and never deletes.
	 */
	readonly forceExpire?: (key: string) => Promise<void>;
	/** A target over the same backend that cannot reach it. */
	readonly unreachable?: () => ConditionalRecordTarget<V>;
	readonly close?: () => Promise<void>;
}

export interface ConditionalRecordContractInput<V> {
	readonly build: () => Promise<ConditionalRecordHarness<V>>;
	/** Two distinct values, built fresh and equal on every call. */
	readonly values: () => readonly [V, V];
	/**
	 * Mutates a value in place, each mutable part on its own, leaving a part
	 * that is frozen without throwing: proves the store keeps its own copy.
	 * Absent for an immutable value.
	 */
	readonly mutate?: (value: V) => void;
	/**
	 * The names in the target's `unconditional` that remove the key, as a
	 * logout does. Every other one must leave the value it was given.
	 */
	readonly removals?: readonly string[];
	/**
	 * The hooks every harness `build` answers, declared up front, so the case
	 * list is fixed when the suite is built. A declared hook that a harness
	 * lacks fails its case; an undeclared one adds no case.
	 */
	readonly supports?: {
		readonly forceExpire?: boolean;
		readonly unreachable?: boolean;
		/** `unconditional` names every unconditional write of the port. Undeclared: that case is not run. */
		readonly unconditional?: boolean;
	};
}

// ---------------------------------------------------------------------------
// Set scope
// ---------------------------------------------------------------------------

/** One set-scoped port's conditional members. */
export interface ConditionalSetTarget<T> {
	listVersioned(scope: string): Promise<VersionedSet<T>>;
	/** The port's plain listing, when it has one: must agree with `listVersioned`. */
	list?(scope: string): Promise<readonly T[]>;
	createIf(item: T, expected: StoreGeneration | null): Promise<ConditionalCreateAnswer>;
	removeIf(
		scope: string,
		id: string,
		expected: StoreGeneration,
	): Promise<ConditionalSetRemoveAnswer>;
	/** Unconditional: leaves the set present and empty, at a new generation. */
	reset(scope: string): Promise<void>;
	/** A member's own update, when the port has one: must keep the set's generation. */
	updateMember?(scope: string, id: string): Promise<void>;
	/** The port's unconditional membership writes, by name. */
	readonly unconditional?: Readonly<Record<string, (item: T) => Promise<void>>>;
}

/** What one case runs over. */
export interface ConditionalSetHarness<T> {
	readonly store: ConditionalSetTarget<T>;
	/** The same backend through a second instance. Absent: `store` again, with no cross-process proof. */
	readonly second?: ConditionalSetTarget<T>;
	/**
	 * Moves the backend's clock past any retention deadline the store set
	 * (`scope` names the set the case expires). It never judges membership,
	 * and never deletes: that an emptied set's tombstone expires and a set
	 * holding a member does not is the store's own doing.
	 */
	readonly forceExpire?: (scope: string) => Promise<void>;
	/** A target over the same backend that cannot reach it. */
	readonly unreachable?: () => ConditionalSetTarget<T>;
	readonly close?: () => Promise<void>;
}

export interface ConditionalSetContractInput<T> {
	readonly build: () => Promise<ConditionalSetHarness<T>>;
	/** `n` distinct items of `scope`, equal on every call with the same arguments. */
	readonly items: (scope: string, n: number) => readonly T[];
	readonly idOf: (item: T) => string;
	/** The scope an item belongs to: every item `items(scope, n)` answers is checked against it. */
	readonly scopeOf: (item: T) => string;
	/**
	 * Mutates an item in place, never its id or scope, each mutable part on its
	 * own, leaving a part that is frozen without throwing: proves the store
	 * keeps its own copy. Absent for an immutable item.
	 */
	readonly mutate?: (item: T) => void;
	/**
	 * The hooks every harness `build` answers, declared up front, so the case
	 * list is fixed when the suite is built. A declared hook that a harness
	 * lacks fails its case; an undeclared one adds no case.
	 */
	readonly supports?: {
		readonly forceExpire?: boolean;
		readonly unreachable?: boolean;
		/** Every target has `updateMember`. Undeclared: that case is not run. */
		readonly updateMember?: boolean;
		/** Every target has `list`. Undeclared: that case is not run. */
		readonly list?: boolean;
		/** `unconditional` names every unconditional membership write of the port. Undeclared: that case is not run. */
		readonly unconditional?: boolean;
	};
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/** A key or scope no other case uses, on a backend cases may share. */
const fresh = (label: string): string => `cw-${label}-${randomUUID()}`;

/**
 * A promise whose await resumes the caller exactly `n` microtasks later, or
 * after one macrotask for `-1`. A race never awaits a delay of `0`, so its
 * second call starts in the same tick as its first.
 */
const pause = (n: number): Promise<void> => {
	if (n < 0) return new Promise<void>((resolve) => setImmediate(resolve));
	if (n <= 1) return Promise.resolve();
	return (async () => {
		for (let i = 1; i < n; i += 1) await null;
	})();
};

/** The delays a race is run over: every microtask count up to 8, then one macrotask (`-1`). */
const RACE_DELAYS: readonly number[] = [0, 1, 2, 3, 4, 5, 6, 7, 8, -1];

/** How many rounds a two-writer race runs. */
const RACE_ROUNDS = 20;

/** The case that stands for cases left out, so the gap shows in the runner's output. */
const notRun = (what: string, hook: string): ContractCase => ({
	name: `not run: ${what} (supports.${hook} not declared)`,
	run: async () => {},
});

/** `hook`, or a failure saying the declared hook is missing. */
function declared<H>(hook: H | undefined, name: string): H {
	if (hook === undefined) {
		assert.fail(`supports.${name} is declared, and the harness gives no ${name}`);
	}
	return hook;
}

/** A case that builds a harness, runs `body` over it and closes it. */
function harnessCase<H extends { readonly close?: () => Promise<void> }>(
	build: () => Promise<H>,
	name: string,
	body: (harness: H) => Promise<void>,
): ContractCase {
	return {
		name,
		run: async () => {
			const harness = await build();
			try {
				await body(harness);
			} finally {
				await harness.close?.();
			}
		},
	};
}

const isConflictOrMissing = (outcome: string): boolean =>
	outcome === "conflict" || outcome === "missing";

/** Whether `write` resolved. A write that throws has an unknown effect, so a case asserts nothing of it. */
const resolved = async (write: Promise<unknown>): Promise<boolean> => {
	try {
		await write;
		return true;
	} catch {
		return false;
	}
};

// ---------------------------------------------------------------------------
// conditionalRecordContract
// ---------------------------------------------------------------------------

/** A target whose every answer is read by core's readers: a malformed answer throws. */
function readRecord<V>(target: ConditionalRecordTarget<V>) {
	return {
		get: async (key: string) => readVersioned(await target.getVersioned(key)),
		live: async (key: string): Promise<Versioned<V>> => {
			const read = readVersioned(await target.getVersioned(key));
			assert.notEqual(read, null, `${key} is live`);
			return read as Versioned<V>;
		},
		replace: async (key: string, expected: StoreGeneration, value: V) =>
			readConditionalReplaceAnswer(await target.replaceIf(key, expected, value)),
		remove: async (key: string, expected: StoreGeneration) =>
			readConditionalRemoveAnswer(await target.removeIf(key, expected)),
	};
}

/** The cases of the record-scoped conditional-write contract over the harnesses `input` builds. */
export function conditionalRecordContract<V>(
	input: ConditionalRecordContractInput<V>,
): readonly ContractCase[] {
	const test = (
		name: string,
		body: (
			store: ReturnType<typeof readRecord<V>>,
			harness: ConditionalRecordHarness<V>,
			raw: ConditionalRecordTarget<V>,
		) => Promise<void>,
	): ContractCase =>
		harnessCase(input.build, name, (harness) =>
			body(readRecord(harness.store), harness, harness.store),
		);
	const both = (harness: ConditionalRecordHarness<V>) =>
		[harness.store, harness.second ?? harness.store] as const;

	/** A live record of a new key at value `0`, and its read. */
	const seeded = async (raw: ConditionalRecordTarget<V>, label: string) => {
		const key = fresh(label);
		await raw.put(key, input.values()[0]);
		return { key, read: await readRecord(raw).live(key) };
	};

	const cases: ContractCase[] = [
		test("a versioned read of a key never written answers null", async (store) => {
			assert.equal(await store.get(fresh("absent")), null);
		}),

		test("a created record is read back whole, at a well-formed generation", async (_store, _h, raw) => {
			const { read } = await seeded(raw, "create");
			assert.deepStrictEqual(read.value, input.values()[0]);
		}),

		test("a replace at the current generation answers updated, at a new generation the record is then read at", async (store, _h, raw) => {
			const { key, read } = await seeded(raw, "replace");
			const answer = await store.replace(key, read.generation, input.values()[1]);
			assert.equal(answer.outcome, "updated");
			assert.ok(answer.outcome === "updated");
			assert.notEqual(answer.generation, read.generation);
			const after = await store.live(key);
			assert.deepStrictEqual(after.value, input.values()[1]);
			assert.equal(after.generation, answer.generation);
		}),

		test("a replace at a stale generation answers conflict and changes nothing", async (store, _h, raw) => {
			const { key, read } = await seeded(raw, "stale");
			const moved = await store.replace(key, read.generation, input.values()[1]);
			assert.ok(moved.outcome === "updated");
			assert.equal(
				(await store.replace(key, read.generation, input.values()[0])).outcome,
				"conflict",
			);
			const after = await store.live(key);
			assert.deepStrictEqual(after.value, input.values()[1]);
			assert.equal(after.generation, moved.generation);
		}),

		test("a replace never creates: an absent key and a removed one answer missing and stay absent", async (store, _h, raw) => {
			const { read: foreign } = await seeded(raw, "foreign");
			const absent = fresh("never");
			assert.equal(
				(await store.replace(absent, foreign.generation, input.values()[0])).outcome,
				"missing",
			);
			assert.equal(await store.get(absent), null);
			const { key, read } = await seeded(raw, "removed");
			assert.equal((await store.remove(key, read.generation)).outcome, "removed");
			assert.equal(
				(await store.replace(key, read.generation, input.values()[1])).outcome,
				"missing",
			);
			assert.equal(await store.get(key), null);
		}),

		test("a removal answers removed at the current generation, conflict at a stale one, and missing for an absent key", async (store, _h, raw) => {
			const { key, read } = await seeded(raw, "remove");
			const moved = await store.replace(key, read.generation, input.values()[1]);
			assert.ok(moved.outcome === "updated");
			assert.equal((await store.remove(key, read.generation)).outcome, "conflict");
			assert.deepStrictEqual((await store.live(key)).value, input.values()[1]);
			assert.equal((await store.remove(key, moved.generation)).outcome, "removed");
			assert.equal(await store.get(key), null);
			assert.equal((await store.remove(key, moved.generation)).outcome, "missing");
		}),

		test("a record removed and created again with the same value is at a new generation, and the old one answers conflict", async (store, _h, raw) => {
			const { key, read } = await seeded(raw, "aba");
			assert.equal((await store.remove(key, read.generation)).outcome, "removed");
			await raw.put(key, input.values()[0]);
			const again = await store.live(key);
			assert.deepStrictEqual(again.value, read.value);
			assert.notEqual(again.generation, read.generation);
			assert.equal(
				(await store.replace(key, read.generation, input.values()[1])).outcome,
				"conflict",
			);
			assert.equal((await store.remove(key, read.generation)).outcome, "conflict");
			assert.equal((await store.live(key)).generation, again.generation);
		}),

		test("a replace with the same value still issues a new generation", async (store, _h, raw) => {
			const { key, read } = await seeded(raw, "same");
			const answer = await store.replace(key, read.generation, input.values()[0]);
			assert.ok(answer.outcome === "updated");
			assert.notEqual(answer.generation, read.generation);
			assert.equal(
				(await store.replace(key, read.generation, input.values()[1])).outcome,
				"conflict",
			);
		}),

		test("of concurrent replaces at one generation through two instances, exactly one is updated", async (_store, harness, raw) => {
			const [a, b] = both(harness);
			const { key, read } = await seeded(raw, "race-replace");
			const writers = Array.from({ length: RACE_ROUNDS }, (_, i) => {
				const target = readRecord(i % 2 === 0 ? a : b);
				return target.replace(key, read.generation, input.values()[i % 2]);
			});
			const answers = await Promise.all(writers);
			const updated = answers.flatMap((answer, i) =>
				answer.outcome === "updated" ? [{ answer, i }] : [],
			);
			assert.equal(updated.length, 1, `updated: ${updated.length} of ${RACE_ROUNDS}`);
			assert.deepStrictEqual(
				answers.filter((answer) => answer.outcome !== "updated").map((answer) => answer.outcome),
				Array(RACE_ROUNDS - 1).fill("conflict"),
			);
			const winner = updated[0];
			assert.ok(winner !== undefined && winner.answer.outcome === "updated");
			const after = await readRecord(a).live(key);
			assert.deepStrictEqual(after.value, input.values()[winner.i % 2]);
			assert.equal(after.generation, winner.answer.generation);
		}),

		test("of concurrent removals at one generation through two instances, exactly one is removed", async (_store, harness, raw) => {
			const [a, b] = both(harness);
			for (let round = 0; round < RACE_ROUNDS; round += 1) {
				const { key, read } = await seeded(raw, `race-remove-${round}`);
				const first = readRecord(round % 2 === 0 ? a : b).remove(key, read.generation);
				const delay = RACE_DELAYS[round % RACE_DELAYS.length] ?? 0;
				if (delay !== 0) await pause(delay);
				const second = readRecord(round % 2 === 0 ? b : a).remove(key, read.generation);
				const answers = await Promise.all([first, second]);
				const outcomes = answers.map((answer) => answer.outcome);
				assert.equal(
					outcomes.filter((outcome) => outcome === "removed").length,
					1,
					`round ${round}: ${outcomes.join(" / ")}`,
				);
				// The loser met a record already removed: `missing`, or `conflict` from a label read before.
				assert.ok(
					outcomes.every((outcome) => outcome === "removed" || isConflictOrMissing(outcome)),
					`round ${round}: ${outcomes.join(" / ")}`,
				);
				assert.equal(await readRecord(a).get(key), null);
			}
		}),

		test("a replace racing a removal at one generation, either started first: exactly one wins, and the record is what the winner left", async (_store, harness, raw) => {
			const [a, b] = both(harness);
			for (let round = 0; round < RACE_ROUNDS * 2; round += 1) {
				const { key, read } = await seeded(raw, `race-mixed-${round}`);
				const [replacer, remover] = round % 2 === 0 ? [a, b] : [b, a];
				const replaceFirst = Math.floor(round / 2) % 2 === 0;
				const replace = () => readRecord(replacer).replace(key, read.generation, input.values()[1]);
				const remove = () => readRecord(remover).remove(key, read.generation);
				const started = replaceFirst ? replace() : remove();
				const delay = RACE_DELAYS[round % RACE_DELAYS.length] ?? 0;
				if (delay !== 0) await pause(delay);
				const then = replaceFirst ? remove() : replace();
				const [one, other] = await Promise.all([started, then]);
				const replaced = (replaceFirst ? one : other) as ConditionalReplaceAnswer;
				const removed = (replaceFirst ? other : one) as ConditionalRemoveAnswer;
				const after = await readRecord(a).get(key);
				const where = `round ${round}, ${replaceFirst ? "replace" : "removal"} first`;
				if (replaced.outcome === "updated") {
					assert.equal(removed.outcome, "conflict", where);
					assert.notEqual(after, null, where);
					assert.deepStrictEqual(after?.value, input.values()[1], where);
					assert.equal(after?.generation, replaced.generation, where);
				} else {
					assert.equal(removed.outcome, "removed", `${where}: no writer won`);
					// The replace met a record already removed: `missing`, or `conflict` from a label read before.
					assert.ok(isConflictOrMissing(replaced.outcome), `${where}: ${replaced.outcome}`);
					assert.equal(after, null, where);
				}
			}
		}),

		test("a versioned read is one snapshot: read with a concurrent replace, its value and generation are both before or both after", async (_store, harness, raw) => {
			const [a, b] = both(harness);
			for (const readFirst of [true, false]) {
				for (const delay of RACE_DELAYS) {
					const { key, read } = await seeded(raw, "snapshot");
					const reader = readRecord(readFirst ? a : b);
					const writer = readRecord(readFirst ? b : a);
					let seen: Promise<Versioned<V> | null>;
					let written: Promise<ConditionalReplaceAnswer>;
					if (readFirst) {
						seen = reader.get(key);
						if (delay !== 0) await pause(delay);
						written = writer.replace(key, read.generation, input.values()[1]);
					} else {
						written = writer.replace(key, read.generation, input.values()[1]);
						if (delay !== 0) await pause(delay);
						seen = reader.get(key);
					}
					const [snapshot, answer] = await Promise.all([seen, written]);
					assert.ok(answer.outcome === "updated");
					const where = `read ${readFirst ? "first" : "second"}, delay ${delay}`;
					assert.ok(snapshot !== null, where);
					if (isDeepStrictEqual(snapshot.value, input.values()[1])) {
						assert.equal(
							snapshot.generation,
							answer.generation,
							`${where}: the new value at the old generation`,
						);
					} else {
						assert.deepStrictEqual(snapshot.value, input.values()[0], `${where}: neither value`);
						assert.equal(
							snapshot.generation,
							read.generation,
							`${where}: the old value at another generation`,
						);
						assert.equal(
							(await writer.replace(key, snapshot.generation, input.values()[0])).outcome,
							"conflict",
							`${where}: the old value at the new generation`,
						);
					}
				}
			}
		}),

		test("missing and conflict write nothing: the current generation still writes afterwards", async (store, _h, raw) => {
			const { key, read } = await seeded(raw, "nothing");
			const moved = await store.replace(key, read.generation, input.values()[1]);
			assert.ok(moved.outcome === "updated");
			assert.equal(
				(await store.replace(key, read.generation, input.values()[0])).outcome,
				"conflict",
			);
			assert.equal((await store.remove(key, read.generation)).outcome, "conflict");
			const current = await store.live(key);
			assert.equal(current.generation, moved.generation);
			assert.deepStrictEqual(current.value, input.values()[1]);
			const after = await store.replace(key, moved.generation, input.values()[0]);
			assert.equal(after.outcome, "updated");
			const gone = fresh("missing");
			assert.equal(
				(await store.replace(gone, moved.generation, input.values()[0])).outcome,
				"missing",
			);
			assert.equal(await store.get(gone), null);
		}),

		test("every answer is one core's readers accept", async (_store, _h, raw) => {
			const key = fresh("readers");
			readVersioned(await raw.getVersioned(key));
			await raw.put(key, input.values()[0]);
			const read = readVersioned(await raw.getVersioned(key));
			assert.ok(read !== null);
			const updated = readConditionalReplaceAnswer(
				await raw.replaceIf(key, read.generation, input.values()[1]),
			);
			readConditionalReplaceAnswer(await raw.replaceIf(key, read.generation, input.values()[1]));
			readConditionalRemoveAnswer(await raw.removeIf(key, read.generation));
			assert.ok(updated.outcome === "updated");
			readConditionalRemoveAnswer(await raw.removeIf(key, updated.generation));
			readConditionalRemoveAnswer(await raw.removeIf(key, updated.generation));
			readConditionalReplaceAnswer(await raw.replaceIf(key, updated.generation, input.values()[0]));
		}),

		test("a create over a live record, as a relink does, issues a new generation, the same value included, and the old one answers conflict", async (store, _h, raw) => {
			const { key, read } = await seeded(raw, "overwrite");
			await raw.put(key, input.values()[1]);
			const after = await store.live(key);
			assert.deepStrictEqual(after.value, input.values()[1]);
			assert.notEqual(after.generation, read.generation);
			assert.equal(
				(await store.replace(key, read.generation, input.values()[0])).outcome,
				"conflict",
			);
			assert.equal((await store.remove(key, read.generation)).outcome, "conflict");
			assert.equal((await store.live(key)).generation, after.generation);
			await raw.put(key, input.values()[1]);
			const again = await store.live(key);
			assert.deepStrictEqual(again.value, input.values()[1]);
			assert.notEqual(again.generation, after.generation, "the same value kept the generation");
			assert.equal(
				(await store.replace(key, after.generation, input.values()[0])).outcome,
				"conflict",
			);
		}),

		test("a write through one instance is read through the other at the generation it answered, and the old generation conflicts there", async (_store, harness) => {
			const [a, b] = both(harness);
			const one = readRecord(a);
			const other = readRecord(b);
			const key = fresh("instances");
			await a.put(key, input.values()[0]);
			const read = await other.live(key);
			assert.deepStrictEqual(read.value, input.values()[0]);
			const replaced = await one.replace(key, read.generation, input.values()[1]);
			assert.ok(replaced.outcome === "updated");
			const seen = await other.live(key);
			assert.deepStrictEqual(seen.value, input.values()[1]);
			assert.equal(seen.generation, replaced.generation);
			assert.equal(
				(await other.replace(key, read.generation, input.values()[0])).outcome,
				"conflict",
			);
			assert.equal((await other.remove(key, read.generation)).outcome, "conflict");
			assert.equal((await other.remove(key, replaced.generation)).outcome, "removed");
			assert.equal(await one.get(key), null);
			assert.equal(await other.get(key), null);
		}),
	];

	cases.push(
		input.supports?.unconditional === true
			? test("every unconditional write, a byte-identical rewrite included, moves or ends the generation: the old one then answers conflict or missing", async (store, _h, raw) => {
					const writes = Object.entries(raw.unconditional);
					assert.ok(
						writes.length > 0,
						"supports.unconditional is declared, and the target names no write",
					);
					const removals = new Set(input.removals ?? []);
					for (const name of removals) {
						assert.ok(
							name in raw.unconditional,
							`removals names ${name}, which the target does not`,
						);
					}
					const ran = new Set<string>();
					for (const [[name, write], same] of writes.flatMap((entry) => [
						[entry, true] as const,
						[entry, false] as const,
					])) {
						const { key, read } = await seeded(raw, `legacy-${name}`);
						const given = input.values()[same ? 0 : 1];
						if (!(await resolved(write(key, given)))) continue;
						ran.add(name);
						const left = await store.get(key);
						if (removals.has(name)) {
							assert.equal(left, null, `${name} is a removal, and left the record`);
						} else {
							assert.notEqual(
								left,
								null,
								`${name} removed the record, and is not named in removals`,
							);
							assert.deepStrictEqual(
								left?.value,
								given,
								`${name} left another value than it was given`,
							);
						}
						assert.notEqual(
							left?.generation,
							read.generation,
							`${name} kept the generation, given ${same ? "the same value" : "another value"}`,
						);
						const replaced = await store.replace(key, read.generation, input.values()[1]);
						assert.ok(
							isConflictOrMissing(replaced.outcome),
							`${name}: replace answered ${replaced.outcome}`,
						);
						const removed = await store.remove(key, read.generation);
						assert.ok(
							isConflictOrMissing(removed.outcome),
							`${name}: removal answered ${removed.outcome}`,
						);
						assert.deepStrictEqual(
							await store.get(key),
							left,
							`${name}: a refused write changed the record`,
						);
					}
					for (const [name] of writes) {
						assert.ok(ran.has(name), `${name} threw given the same value and another`);
					}
				})
			: notRun("the unconditional-write case", "unconditional"),
	);

	cases.push(
		input.supports?.unconditional === true
			? test("an unconditional write racing a replace at one generation, either started first, is serialised with it: a removal leaves the record absent, and no replace outlives the write", async (_store, harness, raw) => {
					const [a, b] = both(harness);
					const writes = Object.keys(raw.unconditional);
					assert.ok(
						writes.length > 0,
						"supports.unconditional is declared, and the target names no write",
					);
					for (const name of writes) {
						const removes = (input.removals ?? []).includes(name);
						let ran = 0;
						for (let round = 0; round < RACE_ROUNDS * 2; round += 1) {
							const { key, read } = await seeded(raw, `race-${name}-${round}`);
							const [writer, replacer] = round % 2 === 0 ? [a, b] : [b, a];
							const write = declared(writer.unconditional[name], name);
							const writeFirst = Math.floor(round / 2) % 2 === 0;
							// Both values, so a write that refuses one of them still races.
							const given = input.values()[Math.floor(round / 4) % 2];
							const unconditional = () => resolved(write(key, given));
							const replace = () =>
								readRecord(replacer).replace(key, read.generation, input.values()[1]);
							const started = writeFirst ? unconditional() : replace();
							const delay = RACE_DELAYS[round % RACE_DELAYS.length] ?? 0;
							if (delay !== 0) await pause(delay);
							const then = writeFirst ? replace() : unconditional();
							const [one, other] = await Promise.all([started, then]);
							const wrote = (writeFirst ? one : other) as boolean;
							const replaced = (writeFirst ? other : one) as ConditionalReplaceAnswer;
							if (!wrote) continue;
							ran += 1;
							const after = await readRecord(a).get(key);
							const where = `${name}, round ${round}, ${writeFirst ? "the write" : "the replace"} first`;
							if (removes) {
								assert.equal(after, null, `${where}: the record outlived the removal`);
								continue;
							}
							assert.notEqual(after, null, where);
							assert.deepStrictEqual(after?.value, given, `${where}: the write's value was lost`);
							assert.notEqual(
								after?.generation,
								read.generation,
								`${where}: the write kept the generation`,
							);
							if (replaced.outcome === "updated") {
								assert.notEqual(
									after?.generation,
									replaced.generation,
									`${where}: the replace outlived the write`,
								);
							}
						}
						assert.ok(ran > 0, `${name} threw in every round`);
					}
				})
			: notRun("the unconditional-write race case", "unconditional"),
	);

	const mutate = input.mutate;
	cases.push(
		mutate === undefined
			? { name: "not run: the aliasing case (no mutate given)", run: async () => {} }
			: test("the store keeps its own copy: changing a value written or read changes nothing stored", async (store, _h, raw) => {
					const key = fresh("alias");
					const written = input.values()[0];
					await raw.put(key, written);
					mutate(written);
					const read = await store.live(key);
					assert.deepStrictEqual(read.value, input.values()[0], "the value handed to put");
					mutate(read.value);
					assert.deepStrictEqual(
						(await store.live(key)).value,
						input.values()[0],
						"the value read back",
					);
					const next = input.values()[1];
					const answer = await store.replace(key, (await store.live(key)).generation, next);
					assert.ok(answer.outcome === "updated");
					mutate(next);
					assert.deepStrictEqual(
						(await store.live(key)).value,
						input.values()[1],
						"the value handed to replaceIf",
					);
				}),
	);

	cases.push(
		input.supports?.forceExpire === true
			? test("an expired record reads as gone, and answers missing to a replace and to a removal made with no read after the expiry", async (store, harness, raw) => {
					const expire = declared(harness.forceExpire, "forceExpire");
					const replaced = await seeded(raw, "expire-replace");
					await expire(replaced.key);
					assert.equal(
						(await store.replace(replaced.key, replaced.read.generation, input.values()[1]))
							.outcome,
						"missing",
					);
					assert.equal(await store.get(replaced.key), null);
					const removed = await seeded(raw, "expire-remove");
					await expire(removed.key);
					assert.equal(
						(await store.remove(removed.key, removed.read.generation)).outcome,
						"missing",
					);
					assert.equal(await store.get(removed.key), null);
					const read = await seeded(raw, "expire-read");
					await expire(read.key);
					assert.equal(await store.get(read.key), null);
				})
			: notRun("the expiry case", "forceExpire"),
	);

	cases.push(
		input.supports?.unreachable === true
			? test("a store that cannot reach its backend rejects every member, never answering null or missing", async (_store, harness, raw) => {
					const unreachable = declared(harness.unreachable, "unreachable")();
					const { key, read } = await seeded(raw, "outage");
					await assert.rejects(unreachable.getVersioned(key), "getVersioned");
					await assert.rejects(
						unreachable.getVersioned(fresh("outage-absent")),
						"getVersioned of an absent key",
					);
					await assert.rejects(
						unreachable.put(fresh("outage-create"), input.values()[0]),
						"create",
					);
					await assert.rejects(
						unreachable.replaceIf(key, read.generation, input.values()[1]),
						"replaceIf",
					);
					await assert.rejects(
						unreachable.replaceIf(fresh("outage-absent"), read.generation, input.values()[1]),
						"replaceIf of an absent key",
					);
					await assert.rejects(unreachable.removeIf(key, read.generation), "removeIf");
					if (input.supports?.unconditional === true) {
						assert.deepStrictEqual(
							Object.keys(unreachable.unconditional).sort(),
							Object.keys(raw.unconditional).sort(),
							"the unreachable target names the same unconditional writes",
						);
						for (const [name, write] of Object.entries(unreachable.unconditional)) {
							await assert.rejects(write(key, input.values()[1]), name);
						}
					}
				})
			: notRun("the outage case", "unreachable"),
	);

	return cases;
}

// ---------------------------------------------------------------------------
// conditionalSetContract
// ---------------------------------------------------------------------------

/** A target whose every answer is read by core's readers: a malformed answer throws. */
function readSet<T>(target: ConditionalSetTarget<T>) {
	return {
		list: async (scope: string) => readVersionedSet(await target.listVersioned(scope)),
		createIf: async (item: T, expected: StoreGeneration | null) =>
			readConditionalCreateAnswer(await target.createIf(item, expected)),
		remove: async (scope: string, id: string, expected: StoreGeneration) =>
			readConditionalSetRemoveAnswer(await target.removeIf(scope, id, expected)),
	};
}

/** The cases of the set-scoped conditional-write contract over the harnesses `input` builds. */
export function conditionalSetContract<T>(
	input: ConditionalSetContractInput<T>,
): readonly ContractCase[] {
	const { idOf } = input;
	const test = (
		name: string,
		body: (
			store: ReturnType<typeof readSet<T>>,
			harness: ConditionalSetHarness<T>,
			raw: ConditionalSetTarget<T>,
		) => Promise<void>,
	): ContractCase =>
		harnessCase(input.build, name, (harness) =>
			body(readSet(harness.store), harness, harness.store),
		);
	const both = (harness: ConditionalSetHarness<T>) =>
		[harness.store, harness.second ?? harness.store] as const;
	const byId = (items: readonly T[]): T[] =>
		[...items].sort((a, b) => (idOf(a) < idOf(b) ? -1 : idOf(a) > idOf(b) ? 1 : 0));
	const sameItems = (actual: readonly T[], expected: readonly T[], message = "the members"): void =>
		assert.deepStrictEqual(byId(actual), byId(expected), message);
	/** Two reads of a set agree: the same generation, and the same members in any order. */
	const sameSet = (
		actual: VersionedSet<T>,
		expected: VersionedSet<T>,
		message = "the set",
	): void => {
		assert.equal(actual.generation, expected.generation, `${message}: the generation`);
		sameItems(actual.items, expected.items, message);
	};
	/** `input.items`, checked: `n` items of distinct ids, each of `scope`. */
	const itemsOf = (scope: string, n: number): readonly T[] => {
		const items = input.items(scope, n);
		assert.equal(items.length, n, `items(…, ${n}) answered ${items.length} items`);
		assert.equal(new Set(items.map(idOf)).size, n, `items(…, ${n}) answered a repeated id`);
		for (const item of items) {
			assert.equal(input.scopeOf(item), scope, `items(…, ${n}) answered an item of another scope`);
		}
		return items;
	};

	/** A new scope holding the first `n` of its items, and its generation. */
	const seeded = async (raw: ConditionalSetTarget<T>, label: string, n: number, extra = 0) => {
		const scope = fresh(label);
		const items = itemsOf(scope, n + extra);
		const store = readSet(raw);
		let generation: StoreGeneration | null = null;
		for (const item of items.slice(0, n)) {
			const answer = await store.createIf(item, generation);
			assert.ok(answer.outcome === "created", `seeding ${idOf(item)} answered ${answer.outcome}`);
			generation = answer.generation;
		}
		const read = await store.list(scope);
		assert.notEqual(read.generation, null, "a seeded set has a generation");
		return { scope, items, generation: read.generation as StoreGeneration };
	};

	/** A generation a store issued, for a scope other than the one under test. */
	const foreignGeneration = async (raw: ConditionalSetTarget<T>): Promise<StoreGeneration> =>
		(await seeded(raw, "foreign", 1)).generation;

	/** The one winner of a race answered the generation `scope` is then read at. */
	const winnerRead = async (
		target: ConditionalSetTarget<T>,
		scope: string,
		answers: readonly (ConditionalCreateAnswer | ConditionalSetRemoveAnswer)[],
		where: string,
	): Promise<VersionedSet<T>> => {
		const won = answers.flatMap((answer) =>
			answer.outcome === "created" || answer.outcome === "removed" ? [answer.generation] : [],
		);
		assert.equal(won.length, 1, `${where}: ${won.length} writes landed`);
		const after = await readSet(target).list(scope);
		assert.equal(
			after.generation,
			won[0],
			`${where}: the set is at another generation than the winner answered`,
		);
		return after;
	};

	const cases: ContractCase[] = [
		test("a set never written answers no items and a null generation", async (store) => {
			assert.deepStrictEqual(await store.list(fresh("never")), { items: [], generation: null });
		}),

		test("of two concurrent first creates through two instances, exactly one is created", async (_store, harness) => {
			const [a, b] = both(harness);
			for (let round = 0; round < RACE_ROUNDS; round += 1) {
				const scope = fresh(`first-${round}`);
				const [x, y] = itemsOf(scope, 2) as [T, T];
				const first = readSet(round % 2 === 0 ? a : b).createIf(x, null);
				const delay = RACE_DELAYS[round % RACE_DELAYS.length] ?? 0;
				if (delay !== 0) await pause(delay);
				const second = readSet(round % 2 === 0 ? b : a).createIf(y, null);
				const answers = await Promise.all([first, second]);
				assert.deepStrictEqual(
					answers.map((answer) => answer.outcome).sort(),
					["conflict", "created"],
					`round ${round}`,
				);
				const winner = answers[0].outcome === "created" ? x : y;
				const after = await winnerRead(a, scope, answers, `round ${round}`);
				sameItems(after.items, [winner], `round ${round}`);
			}
		}),

		test("a reset of a set never written leaves it empty at a generation, so a first create then answers conflict", async (store, _h, raw) => {
			const scope = fresh("reset-absent");
			await raw.reset(scope);
			const read = await store.list(scope);
			assert.deepStrictEqual(read.items, []);
			assert.notEqual(read.generation, null);
			const [x] = itemsOf(scope, 1) as [T];
			assert.equal((await store.createIf(x, null)).outcome, "conflict");
			sameSet(await store.list(scope), read);
		}),

		test("a create at a stale generation answers conflict and adds nothing", async (store, _h, raw) => {
			const { scope, items, generation } = await seeded(raw, "stale-create", 1, 2);
			const [x, y, z] = items as [T, T, T];
			const moved = await store.createIf(y, generation);
			assert.ok(moved.outcome === "created");
			assert.equal((await store.createIf(z, generation)).outcome, "conflict");
			const read = await store.list(scope);
			sameItems(read.items, [x, y]);
			assert.equal(read.generation, moved.generation);
		}),

		test("removing the last member keeps the set, empty, at the new generation removed answers", async (store, _h, raw) => {
			const { scope, items, generation } = await seeded(raw, "last", 1, 1);
			const [x, y] = items as [T, T];
			const removed = await store.remove(scope, idOf(x), generation);
			assert.ok(removed.outcome === "removed");
			assert.notEqual(removed.generation, generation);
			assert.deepStrictEqual(await store.list(scope), {
				items: [],
				generation: removed.generation,
			});
			assert.equal((await store.createIf(y, null)).outcome, "conflict");
		}),

		test("of two concurrent removals of different members at one generation through two instances, exactly one is removed", async (_store, harness, raw) => {
			const [a, b] = both(harness);
			for (let round = 0; round < RACE_ROUNDS; round += 1) {
				const { scope, items, generation } = await seeded(raw, `remove-race-${round}`, 2);
				const [x, y] = items as [T, T];
				const first = readSet(round % 2 === 0 ? a : b).remove(scope, idOf(x), generation);
				const delay = RACE_DELAYS[round % RACE_DELAYS.length] ?? 0;
				if (delay !== 0) await pause(delay);
				const second = readSet(round % 2 === 0 ? b : a).remove(scope, idOf(y), generation);
				const answers = await Promise.all([first, second]);
				assert.deepStrictEqual(
					answers.map((answer) => answer.outcome).sort(),
					["conflict", "removed"],
					`round ${round}`,
				);
				const kept = answers[0].outcome === "removed" ? y : x;
				const after = await winnerRead(a, scope, answers, `round ${round}`);
				sameItems(after.items, [kept], `round ${round}: the loser's member is still listed`);
			}
		}),

		test("of concurrent creates of different members at one generation, exactly one is created", async (_store, harness, raw) => {
			const [a, b] = both(harness);
			const writers = 6;
			const { scope, items, generation } = await seeded(raw, "create-race", 1, writers);
			const candidates = items.slice(1);
			const answers = await Promise.all(
				candidates.map((item, i) => readSet(i % 2 === 0 ? a : b).createIf(item, generation)),
			);
			const created = answers.filter((answer) => answer.outcome === "created");
			assert.equal(created.length, 1, `created: ${created.length} of ${writers}`);
			assert.equal((await winnerRead(a, scope, answers, "the creates")).items.length, 2);
		}),

		test("a removal racing a create at one generation, either started first: exactly one wins", async (_store, harness, raw) => {
			const [a, b] = both(harness);
			for (let round = 0; round < RACE_ROUNDS * 2; round += 1) {
				const { scope, items, generation } = await seeded(raw, `mixed-${round}`, 1, 1);
				const [x, y] = items as [T, T];
				const [remover, creator] = round % 2 === 0 ? [a, b] : [b, a];
				const removeFirst = Math.floor(round / 2) % 2 === 0;
				const remove = () => readSet(remover).remove(scope, idOf(x), generation);
				const create = () => readSet(creator).createIf(y, generation);
				const started = removeFirst ? remove() : create();
				const delay = RACE_DELAYS[round % RACE_DELAYS.length] ?? 0;
				if (delay !== 0) await pause(delay);
				const then = removeFirst ? create() : remove();
				const [one, other] = await Promise.all([started, then]);
				const removed = (removeFirst ? one : other) as ConditionalSetRemoveAnswer;
				const created = (removeFirst ? other : one) as ConditionalCreateAnswer;
				const where = `round ${round}, ${removeFirst ? "removal" : "create"} first`;
				const wins = [removed.outcome === "removed", created.outcome === "created"].filter(
					Boolean,
				).length;
				assert.equal(wins, 1, `${where}: ${removed.outcome} / ${created.outcome}`);
				sameItems(
					(await winnerRead(a, scope, [removed, created], where)).items,
					removed.outcome === "removed" ? [] : [x, y],
					where,
				);
			}
		}),

		test("a reset racing a create or a removal at one generation, either started first, is serialised with it: the set ends empty, at a generation neither the read nor the write answered", async (_store, harness, raw) => {
			const [a, b] = both(harness);
			let round = 0;
			for (const write of ["create", "removal"] as const) {
				for (const resetFirst of [true, false]) {
					for (const delay of RACE_DELAYS) {
						const { scope, items, generation } = await seeded(raw, `reset-race-${round}`, 1, 1);
						const [x, y] = items as [T, T];
						const [resetter, writer] = round % 2 === 0 ? [a, b] : [b, a];
						round += 1;
						const conditional = (): Promise<
							ConditionalCreateAnswer | ConditionalSetRemoveAnswer
						> =>
							write === "create"
								? readSet(writer).createIf(y, generation)
								: readSet(writer).remove(scope, idOf(x), generation);
						const reset = () => resetter.reset(scope);
						const started = resetFirst ? reset() : conditional();
						if (delay !== 0) await pause(delay);
						const then = resetFirst ? conditional() : reset();
						const [one, other] = await Promise.all([started, then]);
						const answer = (resetFirst ? other : one) as
							| ConditionalCreateAnswer
							| ConditionalSetRemoveAnswer;
						const where = `${write}, ${resetFirst ? "the reset" : `the ${write}`} first, delay ${delay}`;
						const after = await readSet(a).list(scope);
						assert.deepStrictEqual(after.items, [], `${where}: the reset left a member`);
						assert.ok(after.generation !== null, where);
						assert.notEqual(
							after.generation,
							generation,
							`${where}: the reset kept the generation`,
						);
						if (answer.outcome === "created" || answer.outcome === "removed") {
							assert.notEqual(
								after.generation,
								answer.generation,
								`${where}: the ${write} outlived the reset`,
							);
						}
					}
				}
			}
		}),

		test("a reset of a set already empty moves its generation: the emptying one then answers conflict", async (store, _h, raw) => {
			const { scope, items, generation } = await seeded(raw, "reset-empty", 1, 1);
			const [x, y] = items as [T, T];
			const removed = await store.remove(scope, idOf(x), generation);
			assert.ok(removed.outcome === "removed");
			await raw.reset(scope);
			const read = await store.list(scope);
			assert.deepStrictEqual(read.items, []);
			assert.notEqual(read.generation, null);
			assert.notEqual(read.generation, removed.generation);
			assert.equal((await store.createIf(y, removed.generation)).outcome, "conflict");
		}),

		test("a write through one instance is read through the other at the generation it answered, and the old generation conflicts there", async (_store, harness) => {
			const [a, b] = both(harness);
			const one = readSet(a);
			const other = readSet(b);
			const scope = fresh("instances");
			const [x, y, z] = itemsOf(scope, 3) as [T, T, T];
			const first = await one.createIf(x, null);
			assert.ok(first.outcome === "created");
			const read = await other.list(scope);
			assert.equal(read.generation, first.generation);
			const second = await one.createIf(y, first.generation);
			assert.ok(second.outcome === "created");
			const seen = await other.list(scope);
			assert.equal(seen.generation, second.generation);
			sameItems(seen.items, [x, y]);
			assert.equal((await other.createIf(z, first.generation)).outcome, "conflict");
			assert.equal((await other.remove(scope, idOf(x), first.generation)).outcome, "conflict");
			const removed = await other.remove(scope, idOf(x), second.generation);
			assert.ok(removed.outcome === "removed");
			const back = await one.list(scope);
			assert.equal(back.generation, removed.generation);
			sameItems(back.items, [y]);
		}),

		test("a member removed and created again with the same bytes leaves no generation repeated, and the first answers conflict", async (store, _h, raw) => {
			const { scope, items, generation } = await seeded(raw, "aba", 2, 1);
			const [x, y, z] = items as [T, T, T];
			const removed = await store.remove(scope, idOf(x), generation);
			assert.ok(removed.outcome === "removed");
			const created = await store.createIf(x, removed.generation);
			assert.ok(created.outcome === "created");
			const read = await store.list(scope);
			sameItems(read.items, [x, y]);
			assert.equal(new Set([generation, removed.generation, created.generation]).size, 3);
			assert.equal(read.generation, created.generation);
			assert.equal((await store.createIf(z, generation)).outcome, "conflict");
			assert.equal((await store.remove(scope, idOf(y), generation)).outcome, "conflict");
		}),

		test("a reset after a read moves the generation: the read one then answers conflict", async (store, _h, raw) => {
			const { scope, items, generation } = await seeded(raw, "reset", 2, 1);
			const [x, , z] = items as [T, T, T];
			await raw.reset(scope);
			const read = await store.list(scope);
			assert.deepStrictEqual(read.items, []);
			assert.notEqual(read.generation, null);
			assert.notEqual(read.generation, generation);
			assert.equal((await store.createIf(z, generation)).outcome, "conflict");
			assert.equal((await store.remove(scope, idOf(x), generation)).outcome, "conflict");
			sameSet(await store.list(scope), read);
		}),

		test("removing a member not held answers missing, keeps the generation, and the generation still writes", async (store, _h, raw) => {
			const { scope, items, generation } = await seeded(raw, "absent-member", 1, 2);
			const [x, y, z] = items as [T, T, T];
			assert.equal((await store.remove(scope, idOf(z), generation)).outcome, "missing");
			const read = await store.list(scope);
			assert.equal(read.generation, generation);
			sameItems(read.items, [x]);
			assert.equal((await store.createIf(y, generation)).outcome, "created");
		}),

		test("against an absent set, a removal with a generation answers missing and a create with one answers conflict", async (store, _h, raw) => {
			const generation = await foreignGeneration(raw);
			const scope = fresh("absent-set");
			const [x] = itemsOf(scope, 1) as [T];
			assert.equal((await store.remove(scope, idOf(x), generation)).outcome, "missing");
			assert.equal((await store.createIf(x, generation)).outcome, "conflict");
			assert.deepStrictEqual(await store.list(scope), { items: [], generation: null });
		}),

		test("a versioned set read is one snapshot: read with a concurrent create, its members and generation are both before or both after", async (_store, harness, raw) => {
			const [a, b] = both(harness);
			for (const readFirst of [true, false]) {
				for (const delay of RACE_DELAYS) {
					const { scope, items, generation } = await seeded(raw, "snapshot", 1, 2);
					const [x, y, z] = items as [T, T, T];
					const reader = readSet(readFirst ? a : b);
					const writer = readSet(readFirst ? b : a);
					let seen: Promise<VersionedSet<T>>;
					let written: Promise<ConditionalCreateAnswer>;
					if (readFirst) {
						seen = reader.list(scope);
						if (delay !== 0) await pause(delay);
						written = writer.createIf(y, generation);
					} else {
						written = writer.createIf(y, generation);
						if (delay !== 0) await pause(delay);
						seen = reader.list(scope);
					}
					const [snapshot, answer] = await Promise.all([seen, written]);
					assert.ok(answer.outcome === "created");
					const where = `read ${readFirst ? "first" : "second"}, delay ${delay}`;
					if (snapshot.items.some((item) => idOf(item) === idOf(y))) {
						sameItems(snapshot.items, [x, y], where);
						assert.equal(
							snapshot.generation,
							answer.generation,
							`${where}: the new members at the old generation`,
						);
					} else {
						sameItems(snapshot.items, [x], where);
						assert.ok(snapshot.generation !== null, where);
						assert.equal(
							snapshot.generation,
							generation,
							`${where}: the old members at another generation`,
						);
						assert.equal(
							(await writer.createIf(z, snapshot.generation)).outcome,
							"conflict",
							`${where}: the old members at the new generation`,
						);
					}
				}
			}
		}),

		test("the versioned read lists the members alone", async (store, _h, raw) => {
			const { scope, items } = await seeded(raw, "members", 3);
			sameItems((await store.list(scope)).items, items);
		}),

		test("every answer is one core's readers accept", async (_store, _h, raw) => {
			const scope = fresh("readers");
			const [x, y] = itemsOf(scope, 2) as [T, T];
			readVersionedSet(await raw.listVersioned(scope));
			const created = readConditionalCreateAnswer(await raw.createIf(x, null));
			readConditionalCreateAnswer(await raw.createIf(y, null));
			const read = readVersionedSet(await raw.listVersioned(scope));
			assert.ok(created.outcome === "created" && read.generation !== null);
			readConditionalSetRemoveAnswer(await raw.removeIf(scope, idOf(y), read.generation));
			const removed = readConditionalSetRemoveAnswer(
				await raw.removeIf(scope, idOf(x), read.generation),
			);
			readConditionalSetRemoveAnswer(await raw.removeIf(scope, idOf(x), read.generation));
			assert.ok(removed.outcome === "removed");
			readVersionedSet(await raw.listVersioned(scope));
		}),

		test("a create of a member already held, at the current generation, answers conflict and changes nothing", async (store, _h, raw) => {
			const { scope, items, generation } = await seeded(raw, "held", 2);
			const [x] = items as [T];
			const before = await store.list(scope);
			assert.equal((await store.createIf(x, generation)).outcome, "conflict");
			sameSet(await store.list(scope), before);
		}),
	];

	const mutate = input.mutate;
	cases.push(
		mutate === undefined
			? { name: "not run: the aliasing case (no mutate given)", run: async () => {} }
			: test("the store keeps its own copy: changing a member written or read changes nothing stored", async (store) => {
					const scope = fresh("alias");
					const written = itemsOf(scope, 3);
					let generation: StoreGeneration | null = null;
					for (const item of written) {
						const answer = await store.createIf(item, generation);
						assert.ok(answer.outcome === "created", `creating ${idOf(item)}`);
						generation = answer.generation;
					}
					for (const item of written) mutate(item);
					const read = await store.list(scope);
					sameItems(read.items, itemsOf(scope, 3), "the members handed to createIf");
					for (const item of read.items) mutate(item);
					sameItems((await store.list(scope)).items, itemsOf(scope, 3), "the members read back");
				}),
	);

	cases.push(
		input.supports?.updateMember === true
			? test("a member's own update changes that member and keeps the set's generation", async (store, _h, raw) => {
					const updateMember = declared(raw.updateMember?.bind(raw), "updateMember");
					const { scope, items, generation } = await seeded(raw, "update", 2);
					const [x, y] = items as [T, T];
					await updateMember(scope, idOf(x));
					const read = await store.list(scope);
					assert.equal(read.generation, generation);
					const updated = read.items.find((item) => idOf(item) === idOf(x));
					assert.ok(updated !== undefined, "the updated member is still listed");
					assert.ok(!isDeepStrictEqual(updated, x), "the update left the member as it was");
					sameItems(
						read.items.filter((item) => idOf(item) !== idOf(x)),
						[y],
						"the other members",
					);
				})
			: notRun("the member-update case", "updateMember"),
	);

	cases.push(
		input.supports?.list === true
			? test("the plain listing agrees with the versioned read", async (store, _h, raw) => {
					const list = declared(raw.list?.bind(raw), "list");
					const { scope } = await seeded(raw, "agree", 3);
					sameItems(await list(scope), (await store.list(scope)).items);
				})
			: notRun("the plain-listing case", "list"),
	);

	cases.push(
		input.supports?.unconditional === true
			? test("every unconditional membership write that changes the members moves the generation: the old one then answers conflict", async (store, _h, raw) => {
					const writes = Object.entries(raw.unconditional ?? {});
					assert.ok(
						writes.length > 0,
						"supports.unconditional is declared, and the target names no write",
					);
					for (const [name, write] of writes) {
						let changed = 0;
						for (const target of ["new", "held"] as const) {
							const { scope, items, generation } = await seeded(
								raw,
								`legacy-${name}-${target}`,
								2,
								2,
							);
							const [x, y, z, w] = items as [T, T, T, T];
							try {
								await write(target === "new" ? z : y);
							} catch {
								continue;
							}
							const after = await store.list(scope);
							if (isDeepStrictEqual(byId(after.items), byId([x, y]))) continue;
							changed += 1;
							assert.notEqual(
								after.generation,
								generation,
								`${name} (${target} member) kept the generation`,
							);
							assert.equal((await store.createIf(w, generation)).outcome, "conflict", name);
							assert.equal(
								(await store.remove(scope, idOf(x), generation)).outcome,
								"conflict",
								name,
							);
							sameSet(await store.list(scope), after, `${name}: a refused write changed the set`);
						}
						assert.ok(changed > 0, `${name} changed no member, given a new member or a held one`);
					}
				})
			: notRun("the unconditional-write case", "unconditional"),
	);

	cases.push(
		input.supports?.forceExpire === true
			? test("an emptied set whose tombstone expired reads as absent, and a write with no read after the expiry finds it absent", async (store, harness, raw) => {
					const expire = declared(harness.forceExpire, "forceExpire");
					const written = await seeded(raw, "tombstone-write", 1, 1);
					const [x, y] = written.items as [T, T];
					const removed = await store.remove(written.scope, idOf(x), written.generation);
					assert.ok(removed.outcome === "removed");
					await expire(written.scope);
					assert.equal((await store.createIf(y, removed.generation)).outcome, "conflict");
					assert.equal(
						(await store.remove(written.scope, idOf(x), removed.generation)).outcome,
						"missing",
					);
					const created = await store.createIf(y, null);
					assert.ok(created.outcome === "created");
					assert.notEqual(created.generation, removed.generation);
					assert.notEqual(created.generation, written.generation);
					const read = await seeded(raw, "tombstone-read", 1);
					const [z] = read.items as [T];
					const emptied = await store.remove(read.scope, idOf(z), read.generation);
					assert.ok(emptied.outcome === "removed");
					await expire(read.scope);
					assert.deepStrictEqual(await store.list(read.scope), { items: [], generation: null });
					const removal = await seeded(raw, "tombstone-remove", 1);
					const [w] = removal.items as [T];
					const gone = await store.remove(removal.scope, idOf(w), removal.generation);
					assert.ok(gone.outcome === "removed");
					await expire(removal.scope);
					assert.equal(
						(await store.remove(removal.scope, idOf(w), removal.generation)).outcome,
						"missing",
						"a removal against an expired set",
					);
					for (const written of [true, false]) {
						const what = written ? "a set a reset emptied" : "a set never written, reset";
						const scope = written
							? (await seeded(raw, "tombstone-reset", 2)).scope
							: fresh("tombstone-reset-absent");
						await raw.reset(scope);
						const tombstone = await store.list(scope);
						assert.ok(tombstone.generation !== null, `${what}: the reset left no tombstone`);
						await expire(scope);
						const [u] = itemsOf(scope, 1) as [T];
						assert.equal(
							(await store.createIf(u, tombstone.generation)).outcome,
							"conflict",
							`${what}: a create at the tombstone's generation after the expiry`,
						);
						assert.deepStrictEqual(
							await store.list(scope),
							{ items: [], generation: null },
							`${what}: the tombstone did not expire`,
						);
						const again = await store.createIf(u, null);
						assert.ok(again.outcome === "created", `${what}: the re-create`);
						assert.notEqual(
							again.generation,
							tombstone.generation,
							`${what}: the re-create repeated the tombstone's generation`,
						);
					}
				})
			: notRun("the tombstone expiry case", "forceExpire"),
	);

	cases.push(
		input.supports?.forceExpire === true
			? test("a set that holds a member does not expire, one revived from its tombstone included: the clock moved past every deadline leaves it as it was", async (store, harness, raw) => {
					const expire = declared(harness.forceExpire, "forceExpire");
					const held = await seeded(raw, "held-set", 2);
					const fromRemoval = await seeded(raw, "held-revived", 1, 1);
					const [x, y] = fromRemoval.items as [T, T];
					const emptied = await store.remove(fromRemoval.scope, idOf(x), fromRemoval.generation);
					assert.ok(emptied.outcome === "removed");
					assert.equal((await store.createIf(y, emptied.generation)).outcome, "created");
					const fromReset = fresh("held-reset");
					await raw.reset(fromReset);
					const tombstone = await store.list(fromReset);
					assert.ok(tombstone.generation !== null, "a reset leaves a generation");
					const [z] = itemsOf(fromReset, 1) as [T];
					assert.equal((await store.createIf(z, tombstone.generation)).outcome, "created");
					const sets = [
						{ scope: held.scope, what: "a set created" },
						{ scope: fromRemoval.scope, what: "a set revived from a removal's tombstone" },
						{ scope: fromReset, what: "a set revived from a reset's tombstone" },
					];
					const before = await Promise.all(
						sets.map(async (set) => ({ ...set, read: await store.list(set.scope) })),
					);
					for (const { scope } of sets) await expire(scope);
					for (const { scope, what, read } of before) sameSet(await store.list(scope), read, what);
				})
			: notRun("the held-set expiry case", "forceExpire"),
	);

	cases.push(
		input.supports?.forceExpire === true
			? test("a set created again after its tombstone expired is at a generation it is then read at, never one seen before", async (store, harness) => {
					const expire = declared(harness.forceExpire, "forceExpire");
					const scope = fresh("recreate");
					const [x, y, z] = itemsOf(scope, 3) as [T, T, T];
					const seen = new Set<StoreGeneration>();
					const first = await store.createIf(x, null);
					assert.ok(first.outcome === "created");
					seen.add(first.generation);
					const second = await store.createIf(y, first.generation);
					assert.ok(second.outcome === "created");
					seen.add(second.generation);
					const removedX = await store.remove(scope, idOf(x), second.generation);
					assert.ok(removedX.outcome === "removed");
					seen.add(removedX.generation);
					const removedY = await store.remove(scope, idOf(y), removedX.generation);
					assert.ok(removedY.outcome === "removed");
					seen.add(removedY.generation);
					await expire(scope);
					const created = await store.createIf(z, null);
					assert.ok(created.outcome === "created");
					assert.ok(!seen.has(created.generation), "a generation seen before was issued again");
					const read = await store.list(scope);
					assert.equal(read.generation, created.generation);
					sameItems(read.items, [z]);
				})
			: notRun("the re-create after expiry case", "forceExpire"),
	);

	cases.push(
		input.supports?.unreachable === true
			? test("a store that cannot reach its backend rejects every member", async (_store, harness, raw) => {
					const unreachable = declared(harness.unreachable, "unreachable")();
					const { scope, items, generation } = await seeded(raw, "outage", 1, 1);
					const [x, y] = items as [T, T];
					await assert.rejects(unreachable.listVersioned(scope), "listVersioned");
					await assert.rejects(
						unreachable.listVersioned(fresh("outage-absent")),
						"listVersioned of an absent set",
					);
					if (input.supports?.list === true) {
						await assert.rejects(
							declared(unreachable.list?.bind(unreachable), "list")(scope),
							"list",
						);
					}
					await assert.rejects(unreachable.createIf(y, generation), "createIf");
					await assert.rejects(
						unreachable.createIf(itemsOf(fresh("outage-new"), 1)[0] as T, null),
						"createIf of a first member",
					);
					await assert.rejects(unreachable.removeIf(scope, idOf(x), generation), "removeIf");
					await assert.rejects(unreachable.reset(scope), "reset");
					if (input.supports?.updateMember === true) {
						const updateMember = declared(
							unreachable.updateMember?.bind(unreachable),
							"updateMember",
						);
						await assert.rejects(updateMember(scope, idOf(x)), "updateMember");
					}
					if (input.supports?.unconditional === true) {
						assert.deepStrictEqual(
							Object.keys(unreachable.unconditional ?? {}).sort(),
							Object.keys(raw.unconditional ?? {}).sort(),
							"the unreachable target names the same unconditional writes",
						);
						for (const [name, write] of Object.entries(unreachable.unconditional ?? {})) {
							await assert.rejects(write(y), name);
						}
					}
				})
			: notRun("the outage case", "unreachable"),
	);

	return cases;
}
