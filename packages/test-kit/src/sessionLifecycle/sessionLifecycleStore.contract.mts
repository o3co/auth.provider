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
 * The contract suite of core's `SessionLifecycleStore` port: a record per
 * sid whose state only moves forward (`active` → `closing` → `closed`);
 * a join that lands only while the record is active and the session has not
 * ended, never once a close has committed, raced through two instances; a
 * close that commits once, keeping the participants as its snapshot and the
 * work they make, idempotent and resumable; a completion applied only at
 * the generation read, one winner of a race, the record closed with its last
 * item; a listing of closing records; a record kept until its retention and
 * then gone whole; an outage rejected, never answered as `missing`, `null`,
 * `closed` or `refused`; and every answer one core's readers accept, so a
 * malformed one fails the case.
 *
 * A hook a harness may lack is declared in `supports`, so the case list is
 * fixed when the suite is built: an undeclared hook's cases are left out,
 * and one passing case names what was not run; a hook declared and missing
 * fails its case. Each case builds a fresh harness, works on sids of its
 * own, and closes it.
 */

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
	DEFAULT_CLOCK_SKEW_MS,
	readConditionalReplaceAnswer,
	readSessionCloseAnswer,
	readSessionJoinAnswer,
	readSessionLifecycleListing,
	readSessionOpenAnswer,
	readVersionedSessionLifecycle,
	type SessionCloseAnswer,
	type SessionCloseRequest,
	type SessionLifecycleRecord,
	type SessionLifecycleStore,
	type SessionParticipant,
	type StoreGeneration,
	sessionCloseItemOf,
	type Versioned,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";

/** What one case runs over. */
export interface SessionLifecycleStoreHarness {
	readonly store: SessionLifecycleStore;
	/**
	 * The same backend through a second instance: another connection, pool or
	 * client. Absent: `store` again, with no cross-process proof.
	 */
	readonly second?: SessionLifecycleStore;
	/**
	 * The store's clock, which the harness moves by hand. Absent: the store
	 * reads a real clock, and the cases that need the time moved short of a
	 * deadline are not run.
	 */
	readonly clock?: {
		/** Epoch milliseconds, as the store reads them. */
		now(): number;
		advance(ms: number): void | Promise<void>;
	};
	/**
	 * Moves the backend's clock past every retention deadline the store set
	 * for the record of `sid`. It never judges what expires, and never
	 * deletes.
	 */
	readonly forceExpire?: (sid: string) => Promise<void>;
	/** A store over the same backend that cannot reach it. */
	readonly unreachable?: () => SessionLifecycleStore;
	readonly close?: () => Promise<void>;
}

export interface SessionLifecycleStoreContractInput {
	readonly build: () => Promise<SessionLifecycleStoreHarness>;
	/**
	 * The hooks every harness `build` answers, declared up front, so the case
	 * list is fixed when the suite is built. A declared hook that a harness
	 * lacks fails its case; an undeclared one runs no case, and one passing
	 * case names what was not run.
	 */
	readonly supports?: {
		readonly clock?: boolean;
		readonly forceExpire?: boolean;
		readonly unreachable?: boolean;
	};
}

const HOUR = 60 * 60 * 1000;

/** How many rounds a race runs. */
const RACE_ROUNDS = 20;

/** The delays a race is run over: every microtask count up to 8, then one macrotask (`-1`). */
const RACE_DELAYS: readonly number[] = [0, 1, 2, 3, 4, 5, 6, 7, 8, -1];

/**
 * A promise whose await resumes the caller exactly `n` microtasks later, or
 * after one macrotask for `-1`.
 */
const pause = (n: number): Promise<void> => {
	if (n < 0) return new Promise<void>((resolve) => setImmediate(resolve));
	if (n <= 1) return Promise.resolve();
	return (async () => {
		for (let i = 1; i < n; i += 1) await null;
	})();
};

/** A sid no other case uses, on a backend cases may share. */
const freshSid = (label: string): string => `sl-${label}-${randomUUID()}`;

const participant = (
	kind: SessionParticipant["kind"],
	id: string,
	data = `${kind}/${id}`,
): SessionParticipant => ({
	kind,
	id,
	data,
});

/** A close request: one step, and one item per relying party and per family. */
const request = (overrides: Partial<SessionCloseRequest> = {}): SessionCloseRequest => ({
	cause: "rp_logout",
	steps: ["user_session"],
	perParticipant: ["rp", "family"],
	retainMs: HOUR,
	...overrides,
});

/** `items`, sorted: a store may keep work items in any order. */
const sorted = (items: readonly string[]): string[] => [...items].sort();

/** The epoch milliseconds the store reads now. */
const nowOf = (harness: SessionLifecycleStoreHarness): number => harness.clock?.now() ?? Date.now();

/** `hook`, or a failure saying the declared hook is missing. */
function declared<H>(hook: H | undefined, name: string): H {
	if (hook === undefined)
		assert.fail(`supports.${name} is declared, and the harness gives no ${name}`);
	return hook;
}

/** The case that stands for cases left out, so the gap shows in the runner's output. */
const notRun = (what: string, hook: string): ContractCase => ({
	name: `not run: ${what} (supports.${hook} not declared)`,
	run: async () => {},
});

/** Whether `value` is a plain object: `Object.prototype` or `null` its prototype. */
const isPlain = (value: unknown): value is Record<string, unknown> => {
	if (typeof value !== "object" || value === null) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
};

/** Throws unless `value` is a plain object whose own keys are exactly `keys`. */
function assertShape(value: unknown, keys: readonly string[], what: string): void {
	assert.ok(isPlain(value), `${what} is a plain object`);
	assert.deepStrictEqual(
		Reflect.ownKeys(value).map(String).sort(),
		[...keys].sort(),
		`${what} names exactly its keys`,
	);
}

/**
 * Throws unless a record is answered whole, as plain data, before any reader
 * copies it: every key named (`close` too, as `undefined`, while active) and
 * no other.
 */
function assertWholeRecord(record: unknown, where: string): void {
	assertShape(
		record,
		["sub", "state", "expiresAt", "participants", "close"],
		`${where}: the record`,
	);
	const { participants, close } = record as Record<string, unknown>;
	assert.ok(Array.isArray(participants), `${where}: participants is an array`);
	for (const p of participants) assertShape(p, ["kind", "id", "data"], `${where}: a participant`);
	if (close !== undefined)
		assertShape(close, ["cause", "closingAt", "pending"], `${where}: the close`);
}

/**
 * A store whose every answer is read by core's readers, so a malformed answer
 * throws, and whose records are checked whole before a reader copies them.
 */
function reading(store: SessionLifecycleStore) {
	const read = async (sid: string) => {
		const raw = await store.read(sid);
		if (raw !== null) assertWholeRecord(raw.value, `read(${sid})`);
		return readVersionedSessionLifecycle(raw);
	};
	return {
		open: async (sid: string, sub: string, expiresAt: Date) =>
			readSessionOpenAnswer(await store.open(sid, sub, expiresAt)).outcome,
		join: async (sid: string, joining: SessionParticipant) =>
			readSessionJoinAnswer(await store.join(sid, joining)).outcome,
		close: async (sid: string, req: SessionCloseRequest = request()) => {
			const raw = await store.beginClose(sid, req);
			if (raw.outcome !== "missing") assertWholeRecord(raw.record, `beginClose(${sid})`);
			return readSessionCloseAnswer(raw);
		},
		complete: async (sid: string, expected: StoreGeneration, item: string) =>
			readConditionalReplaceAnswer(await store.completeIf(sid, expected, item)),
		read,
		live: async (sid: string): Promise<Versioned<SessionLifecycleRecord>> => {
			const answer = await read(sid);
			assert.notEqual(answer, null, `${sid} is live`);
			return answer as Versioned<SessionLifecycleRecord>;
		},
		listClosing: async (limit: number, after?: string) =>
			readSessionLifecycleListing(await store.listClosing(limit, after), limit, after),
		/** Every closing sid, paged `limit` at a time, each page from the last sid of the one before. */
		listAllClosing: async (limit: number): Promise<string[]> => {
			const all: string[] = [];
			let after = "";
			for (;;) {
				const page = readSessionLifecycleListing(
					await store.listClosing(limit, after),
					limit,
					after,
				);
				all.push(...page);
				if (page.length < limit) return all;
				after = page[page.length - 1] as string;
			}
		},
	};
}

type Reading = ReturnType<typeof reading>;

/** A close answer that is a commit: closing or closed, with its record. */
function committed(
	answer: SessionCloseAnswer,
	where = "the close",
): Extract<SessionCloseAnswer, { generation: StoreGeneration }> {
	assert.notEqual(answer.outcome, "missing", `${where} found the record`);
	return answer as Extract<SessionCloseAnswer, { generation: StoreGeneration }>;
}

/** The cases of the `SessionLifecycleStore` contract over the harnesses `input` builds. */
export function sessionLifecycleStoreContract(
	input: SessionLifecycleStoreContractInput,
): readonly ContractCase[] {
	const test = (
		name: string,
		body: (store: Reading, harness: SessionLifecycleStoreHarness) => Promise<void>,
	): ContractCase => ({
		name,
		run: async () => {
			const harness = await input.build();
			try {
				await body(reading(harness.store), harness);
			} finally {
				await harness.close?.();
			}
		},
	});

	/** An end an hour after the store's clock. */
	const later = (harness: SessionLifecycleStoreHarness): Date => new Date(nowOf(harness) + HOUR);

	/** A new sid opened active for `sub`, ending an hour from now, and its end. */
	const opened = async (store: Reading, harness: SessionLifecycleStoreHarness, label: string) => {
		const sid = freshSid(label);
		const expiresAt = later(harness);
		assert.equal(await store.open(sid, "user-1", expiresAt), "opened", `${label}: opened`);
		return { sid, expiresAt };
	};

	const cases: ContractCase[] = [
		test("read answers null for a sid never opened, and listClosing does not name it", async (store) => {
			const sid = freshSid("absent");
			assert.equal(await store.read(sid), null);
			assert.ok(!(await store.listClosing(1000)).includes(sid));
		}),

		test("an opened record is read back active and whole, with no participant and no close, at a well-formed generation", async (store, harness) => {
			const { sid, expiresAt } = await opened(store, harness, "open");
			const read = await store.live(sid);
			assert.deepStrictEqual(read.value, {
				sub: "user-1",
				state: "active",
				expiresAt,
				participants: [],
				close: undefined,
			});
		}),

		test("a repeated open with the same subject and end answers opened and writes nothing; any other open of the sid is refused and writes nothing", async (store, harness) => {
			const { sid, expiresAt } = await opened(store, harness, "reopen");
			const first = await store.live(sid);
			assert.equal(await store.open(sid, "user-1", new Date(expiresAt.getTime())), "opened");
			assert.deepStrictEqual(await store.live(sid), first, "a repeat writes nothing");
			assert.equal(await store.open(sid, "user-2", expiresAt), "refused", "another subject");
			assert.equal(
				await store.open(sid, "user-1", new Date(expiresAt.getTime() + 1)),
				"refused",
				"another end",
			);
			assert.deepStrictEqual(await store.live(sid), first, "a refused open writes nothing");
		}),

		test("an open whose expiresAt has passed is refused and writes nothing", async (store, harness) => {
			const sid = freshSid("late");
			assert.equal(await store.open(sid, "user-1", new Date(nowOf(harness) - HOUR)), "refused");
			assert.equal(await store.read(sid), null);
		}),

		test("a join while active answers joined at a new generation, and a participant joined again is replaced, not repeated", async (store, harness) => {
			const { sid } = await opened(store, harness, "join");
			const before = await store.live(sid);
			assert.equal(await store.join(sid, participant("rp", "client-1")), "joined");
			const one = await store.live(sid);
			assert.notEqual(one.generation, before.generation);
			assert.deepStrictEqual(one.value.participants, [participant("rp", "client-1")]);
			assert.equal(await store.join(sid, participant("family", "fam-1")), "joined");
			assert.equal(await store.join(sid, participant("federation", "google")), "joined");
			assert.equal(await store.join(sid, participant("rp", "client-1", "updated")), "joined");
			const after = await store.live(sid);
			assert.notEqual(after.generation, one.generation);
			const byItem = new Map(after.value.participants.map((p) => [sessionCloseItemOf(p), p]));
			assert.equal(after.value.participants.length, 3, "no participant is held twice");
			assert.deepStrictEqual(byItem.get("rp:client-1"), participant("rp", "client-1", "updated"));
			assert.deepStrictEqual(byItem.get("family:fam-1"), participant("family", "fam-1"));
			assert.deepStrictEqual(byItem.get("federation:google"), participant("federation", "google"));
			assert.equal(after.value.state, "active");
		}),

		test("participants are answered in the order each first joined, a repeat join not moving one, and the closing snapshot keeps it", async (store, harness) => {
			const { sid } = await opened(store, harness, "order");
			// Not the order of the items' bytes, so a store that sorts by them fails.
			const joining = [
				participant("federation", "oidc"),
				participant("rp", "zeta"),
				participant("federation", "apple"),
				participant("family", "f1"),
			];
			for (const p of joining) assert.equal(await store.join(sid, p), "joined");
			assert.equal(await store.join(sid, participant("federation", "oidc", "again")), "joined");
			const order = ["federation:oidc", "rp:zeta", "federation:apple", "family:f1"];
			const live = await store.live(sid);
			assert.deepStrictEqual(live.value.participants.map(sessionCloseItemOf), order);
			const closed = await store.close(sid);
			assert.ok(closed.outcome !== "missing", "the close found the record");
			assert.deepStrictEqual(closed.record.participants.map(sessionCloseItemOf), order);
		}),

		test("a join, a close or a completion of a sid with no record answers missing and creates nothing", async (store, harness) => {
			const sid = freshSid("missing");
			const { sid: other } = await opened(store, harness, "missing-other");
			const foreign = (await store.live(other)).generation;
			assert.equal(await store.join(sid, participant("rp", "client-1")), "missing");
			assert.equal(await store.read(sid), null);
			assert.equal((await store.close(sid)).outcome, "missing");
			assert.equal(await store.read(sid), null);
			assert.equal((await store.complete(sid, foreign, "user_session")).outcome, "missing");
			assert.equal(await store.read(sid), null);
		}),

		test("a close moves the record to closing in one commit: the participants as the snapshot, one work item per step and per participant of the listed kinds, its cause and the time of the commit", async (store, harness) => {
			const { sid, expiresAt } = await opened(store, harness, "close");
			const joined = [
				participant("rp", "client-1"),
				participant("family", "fam-1"),
				participant("federation", "google"),
			];
			for (const p of joined) assert.equal(await store.join(sid, p), "joined");
			const before = await store.live(sid);
			const from = nowOf(harness);
			const answer = committed(
				await store.close(sid, request({ steps: ["user_session", "subject_index"] })),
			);
			const to = nowOf(harness);
			assert.equal(answer.outcome, "closing");
			assert.notEqual(answer.generation, before.generation);
			const { record } = answer;
			assert.equal(record.state, "closing");
			assert.equal(record.sub, "user-1");
			assert.deepStrictEqual(record.expiresAt, expiresAt);
			assert.deepStrictEqual(
				sorted(record.participants.map(sessionCloseItemOf)),
				sorted(joined.map(sessionCloseItemOf)),
			);
			assert.ok(record.close !== undefined);
			assert.equal(record.close.cause, "rp_logout");
			assert.deepStrictEqual(
				sorted(record.close.pending),
				sorted(["user_session", "subject_index", "rp:client-1", "family:fam-1"]),
				"one item per step and per participant of a listed kind; none for the federation",
			);
			const tolerance = harness.clock === undefined ? DEFAULT_CLOCK_SKEW_MS : 0;
			const at = record.close.closingAt.getTime();
			assert.ok(at >= from - tolerance && at <= to + tolerance, "closingAt is the commit's time");
			assert.deepStrictEqual(await store.live(sid), {
				value: record,
				generation: answer.generation,
			});
		}),

		test("no join lands once the close has committed: a join through either instance answers closed and the snapshot is unchanged", async (store, harness) => {
			const { sid } = await opened(store, harness, "after-close");
			assert.equal(await store.join(sid, participant("rp", "client-1")), "joined");
			const answer = committed(await store.close(sid));
			const other = reading(harness.second ?? harness.store);
			assert.equal(await store.join(sid, participant("rp", "client-2")), "closed");
			assert.equal(await other.join(sid, participant("family", "fam-2")), "closed");
			assert.equal(await store.join(sid, participant("rp", "client-1", "again")), "closed");
			assert.deepStrictEqual(await store.live(sid), {
				value: answer.record,
				generation: answer.generation,
			});
		}),

		test("a join racing a close, either started first, through two instances: a join answered joined is in the snapshot with its work item, and one answered closed is in no part of the record", async (_store, harness) => {
			const a = harness.store;
			const b = harness.second ?? harness.store;
			for (let round = 0; round < RACE_ROUNDS * 2; round += 1) {
				const setup = reading(a);
				const { sid } = await opened(setup, harness, `race-${round}`);
				assert.equal(await setup.join(sid, participant("rp", "client-0")), "joined");
				const [joiner, closer] =
					round % 2 === 0 ? [reading(a), reading(b)] : [reading(b), reading(a)];
				const joinFirst = Math.floor(round / 2) % 2 === 0;
				const joining = participant("rp", `client-${round + 1}`);
				const join = () => joiner.join(sid, joining);
				const close = () => closer.close(sid);
				const started = joinFirst ? join() : close();
				const delay = RACE_DELAYS[round % RACE_DELAYS.length] ?? 0;
				if (delay !== 0) await pause(delay);
				const then = joinFirst ? close() : join();
				const [one, other] = await Promise.all([started, then]);
				const joined = (joinFirst ? one : other) as string;
				const closed = committed((joinFirst ? other : one) as SessionCloseAnswer, `round ${round}`);
				const where = `round ${round}, ${joinFirst ? "join" : "close"} first, delay ${delay}`;
				const item = sessionCloseItemOf(joining);
				const after = await setup.live(sid);
				assert.deepStrictEqual(
					after.value.participants,
					closed.record.participants,
					`${where}: the snapshot is the record's`,
				);
				const inSnapshot = closed.record.participants.some((p) => sessionCloseItemOf(p) === item);
				const pending = closed.record.close?.pending ?? [];
				if (joined === "joined") {
					assert.ok(inSnapshot, `${where}: a join answered joined is in the snapshot`);
					assert.ok(pending.includes(item), `${where}: and has its work item`);
				} else {
					assert.equal(joined, "closed", where);
					assert.ok(!inSnapshot, `${where}: a join answered closed is not in the snapshot`);
					assert.ok(!pending.includes(item), `${where}: and makes no work item`);
				}
			}
		}),

		test("a close is idempotent: a repeat through either instance, whatever its request, answers the saved close at the same generation and writes nothing", async (store, harness) => {
			const { sid } = await opened(store, harness, "idempotent");
			assert.equal(await store.join(sid, participant("family", "fam-1")), "joined");
			const first = committed(await store.close(sid));
			const other = reading(harness.second ?? harness.store);
			for (const again of [
				await store.close(sid),
				await other.close(
					sid,
					request({ cause: "expiry", steps: ["other_step"], perParticipant: [] }),
				),
			]) {
				const answer = committed(again, "a repeated close");
				assert.equal(answer.outcome, "closing");
				assert.equal(answer.generation, first.generation, "a repeat writes nothing");
				assert.deepStrictEqual(answer.record, first.record, "a repeat answers the saved close");
			}
			assert.deepStrictEqual(await store.live(sid), {
				value: first.record,
				generation: first.generation,
			});
		}),

		test("a close is resumable: after some items are completed, a repeat answers what is still pending at the current generation, and completing the rest closes the record", async (store, harness) => {
			const { sid } = await opened(store, harness, "resume");
			assert.equal(await store.join(sid, participant("rp", "client-1")), "joined");
			assert.equal(await store.join(sid, participant("rp", "client-2")), "joined");
			const first = committed(await store.close(sid));
			const done = await store.complete(sid, first.generation, "rp:client-1");
			assert.ok(done.outcome === "updated");
			const resumed = committed(
				await store.close(sid, request({ cause: "session_logout" })),
				"the resume",
			);
			assert.equal(resumed.outcome, "closing");
			assert.equal(
				resumed.generation,
				done.generation,
				"the resume answers the current generation",
			);
			assert.equal(resumed.record.close?.cause, "rp_logout", "the first close's cause is kept");
			assert.deepStrictEqual(resumed.record.close?.closingAt, first.record.close?.closingAt);
			assert.deepStrictEqual(
				sorted(resumed.record.close?.pending ?? []),
				sorted(["user_session", "rp:client-2"]),
			);
			let generation = resumed.generation;
			for (const item of resumed.record.close?.pending ?? []) {
				const answer = await store.complete(sid, generation, item);
				assert.ok(answer.outcome === "updated", `${item} completed`);
				generation = answer.generation;
			}
			const end = await store.live(sid);
			assert.equal(end.value.state, "closed");
			assert.deepStrictEqual(end.value.close?.pending, []);
			assert.equal(end.generation, generation);
		}),

		test("completeIf at the current generation answers updated at a new generation the record is then read at; at a stale one conflict, writing nothing", async (store, harness) => {
			const { sid } = await opened(store, harness, "complete");
			const first = committed(
				await store.close(sid, request({ steps: ["user_session", "subject_index"] })),
			);
			const updated = await store.complete(sid, first.generation, "user_session");
			assert.ok(updated.outcome === "updated");
			assert.notEqual(updated.generation, first.generation);
			const after = await store.live(sid);
			assert.equal(after.generation, updated.generation);
			assert.deepStrictEqual(after.value.close?.pending, ["subject_index"]);
			assert.equal(after.value.state, "closing");
			assert.equal(
				(await store.complete(sid, first.generation, "subject_index")).outcome,
				"conflict",
			);
			assert.deepStrictEqual(await store.live(sid), after, "a conflict writes nothing");
			for (const malformed of ["", "has space", 'quote"d']) {
				await assert.rejects(
					harness.store.completeIf(sid, malformed as StoreGeneration, "subject_index"),
					RangeError,
					`a malformed generation (${JSON.stringify(malformed)}) is the caller's error`,
				);
			}
			assert.deepStrictEqual(await store.live(sid), after, "and writes nothing");
		}),

		test("of concurrent completions of one item at one generation through two instances, exactly one is updated", async (_store, harness) => {
			const a = reading(harness.store);
			const b = reading(harness.second ?? harness.store);
			const { sid } = await opened(a, harness, "complete-race");
			const first = committed(
				await a.close(sid, request({ steps: ["user_session", "subject_index"] })),
			);
			const answers = await Promise.all(
				Array.from({ length: RACE_ROUNDS }, (_, i) =>
					(i % 2 === 0 ? a : b).complete(sid, first.generation, "user_session"),
				),
			);
			const outcomes = answers.map((answer) => answer.outcome);
			assert.equal(
				outcomes.filter((outcome) => outcome === "updated").length,
				1,
				outcomes.join(" / "),
			);
			assert.deepStrictEqual(
				outcomes.filter((outcome) => outcome !== "updated"),
				Array(RACE_ROUNDS - 1).fill("conflict"),
			);
			const winner = answers.find((answer) => answer.outcome === "updated");
			const after = await a.live(sid);
			assert.ok(winner?.outcome === "updated");
			assert.equal(after.generation, winner.generation);
			assert.deepStrictEqual(after.value.close?.pending, ["subject_index"]);
		}),

		test("the record is closed in the step that completes its last item, and a close that makes no work item is closed at once", async (store, harness) => {
			const { sid } = await opened(store, harness, "closed");
			const first = committed(
				await store.close(sid, request({ steps: ["user_session"], perParticipant: [] })),
			);
			const last = await store.complete(sid, first.generation, "user_session");
			assert.ok(last.outcome === "updated");
			const after = await store.live(sid);
			assert.equal(after.value.state, "closed");
			assert.equal(after.generation, last.generation);
			const { sid: empty } = await opened(store, harness, "closed-empty");
			assert.equal(await store.join(empty, participant("federation", "google")), "joined");
			const answer = committed(
				await store.close(empty, request({ steps: [], perParticipant: ["rp"] })),
			);
			assert.equal(answer.outcome, "closed");
			assert.equal(answer.record.state, "closed");
			assert.deepStrictEqual(answer.record.close?.pending, []);
			assert.deepStrictEqual(
				answer.record.participants,
				[participant("federation", "google")],
				"a close with no work keeps its snapshot",
			);
			assert.deepStrictEqual(await store.live(empty), {
				value: answer.record,
				generation: answer.generation,
			});
		}),

		test("states only move forward: a closing or a closed record is never opened again, joined, or closed into another state", async (store, harness) => {
			const { sid, expiresAt } = await opened(store, harness, "forward");
			const closing = committed(
				await store.close(sid, request({ steps: ["user_session"], perParticipant: [] })),
			);
			const check = async (state: "closing" | "closed", generation: StoreGeneration) => {
				assert.equal(await store.open(sid, "user-1", expiresAt), "refused", `${state}: open`);
				assert.equal(
					await store.join(sid, participant("rp", "client-1")),
					"closed",
					`${state}: join`,
				);
				const again = committed(await store.close(sid), `${state}: close`);
				assert.equal(again.outcome, state);
				assert.equal(again.generation, generation, `${state}: a close writes nothing`);
				const read = await store.live(sid);
				assert.equal(read.value.state, state);
				assert.equal(read.generation, generation);
			};
			await check("closing", closing.generation);
			const done = await store.complete(sid, closing.generation, "user_session");
			assert.ok(done.outcome === "updated");
			await check("closed", done.generation);
		}),

		test("a closing record is listed, and an active, a closed or an absent one is not; a listing names at most its limit, in ascending order after its cursor, and paging from the last sid reaches every closing record", async (store, harness) => {
			const { sid: active } = await opened(store, harness, "list-active");
			const { sid: closing } = await opened(store, harness, "list-closing");
			const { sid: closing2 } = await opened(store, harness, "list-closing-2");
			const { sid: closed } = await opened(store, harness, "list-closed");
			committed(await store.close(closing));
			committed(await store.close(closing2));
			const ending = committed(
				await store.close(closed, request({ steps: ["user_session"], perParticipant: [] })),
			);
			assert.equal(
				(await store.complete(closed, ending.generation, "user_session")).outcome,
				"updated",
			);
			const listed = await store.listClosing(1000);
			assert.ok(
				listed.includes(closing) && listed.includes(closing2),
				"every closing record is listed",
			);
			for (const sid of [active, closed, freshSid("list-absent")]) {
				assert.ok(!listed.includes(sid), `${sid} is not closing, and is not listed`);
			}
			assert.equal((await store.listClosing(1)).length, 1, "a listing names at most its limit");
			const [first, second] = [closing, closing2].sort((a, b) =>
				Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")),
			) as [string, string];
			const after = await store.listClosing(1000, first);
			assert.ok(!after.includes(first), "a listing starts after its cursor");
			assert.ok(after.includes(second), "and names what follows it");
			const paged = await store.listAllClosing(1);
			assert.ok(
				paged.includes(closing) && paged.includes(closing2),
				"paging one at a time reaches every closing record",
			);
			for (const sid of [active, closed]) assert.ok(!paged.includes(sid), `${sid} is not paged`);
		}),

		test("every answer is one core's readers accept", async (_store, harness) => {
			const raw = harness.store;
			const sid = freshSid("readers");
			readVersionedSessionLifecycle(await raw.read(sid));
			readSessionJoinAnswer(await raw.join(sid, participant("rp", "client-1")));
			readSessionCloseAnswer(await raw.beginClose(sid, request()));
			readSessionOpenAnswer(await raw.open(sid, "user-1", later(harness)));
			readSessionOpenAnswer(await raw.open(sid, "user-2", later(harness)));
			readSessionJoinAnswer(await raw.join(sid, participant("rp", "client-1")));
			const read = readVersionedSessionLifecycle(await raw.read(sid));
			assert.ok(read !== null);
			const answer = committed(readSessionCloseAnswer(await raw.beginClose(sid, request())));
			readSessionCloseAnswer(await raw.beginClose(sid, request()));
			readSessionJoinAnswer(await raw.join(sid, participant("rp", "client-2")));
			readConditionalReplaceAnswer(await raw.completeIf(sid, read.generation, "user_session"));
			const done = readConditionalReplaceAnswer(
				await raw.completeIf(sid, answer.generation, "user_session"),
			);
			assert.ok(done.outcome === "updated");
			readConditionalReplaceAnswer(await raw.completeIf(sid, done.generation, "rp:client-1"));
			readVersionedSessionLifecycle(await raw.read(sid));
			readSessionCloseAnswer(await raw.beginClose(sid, request()));
			readSessionLifecycleListing(await raw.listClosing(5), 5);
		}),

		test("the store keeps its own copies: what it was handed and what it answered can be changed without changing the record", async (store, harness) => {
			const sid = freshSid("copies");
			const expiresAt = later(harness);
			const kept = expiresAt.getTime();
			assert.equal(await store.open(sid, "user-1", expiresAt), "opened");
			const joining = { kind: "rp", id: "client-1", data: "data" } as {
				kind: "rp";
				id: string;
				data: string;
			};
			assert.equal(await store.join(sid, joining), "joined");
			expiresAt.setTime(0);
			joining.id = "changed";
			joining.data = "changed";
			const handedOut = await harness.store.read(sid);
			assert.ok(handedOut !== null);
			const tryTo = (change: () => void): void => {
				try {
					change();
				} catch {
					// A frozen answer is a copy too.
				}
			};
			tryTo(() => (handedOut.value.expiresAt as Date).setTime(0));
			tryTo(() => {
				(handedOut.value.participants[0] as { data: string }).data = "mutated";
			});
			tryTo(() => {
				(handedOut.value.participants as SessionParticipant[]).push(participant("rp", "pushed"));
			});
			const read = await store.live(sid);
			assert.equal(read.value.expiresAt.getTime(), kept);
			assert.deepStrictEqual(read.value.participants, [participant("rp", "client-1", "data")]);
		}),

		test("one sid's writes leave another sid's record and generation as they were", async (store, harness) => {
			const { sid } = await opened(store, harness, "apart");
			const { sid: other } = await opened(store, harness, "apart-other");
			assert.equal(await store.join(other, participant("rp", "client-1")), "joined");
			const before = await store.live(other);
			assert.equal(await store.join(sid, participant("rp", "client-1")), "joined");
			const answer = committed(await store.close(sid));
			for (const item of answer.record.close?.pending ?? []) {
				const now = await store.live(sid);
				assert.equal((await store.complete(sid, now.generation, item)).outcome, "updated");
			}
			assert.deepStrictEqual(await store.live(other), before);
			assert.equal(
				(await store.complete(other, answer.generation, "user_session")).outcome,
				"conflict",
				"a generation fences its own record",
			);
		}),
	];

	if (input.supports?.clock === true) {
		cases.push(
			test("a join or a repeated open from the session's expiresAt on is refused, while the record is still kept active", async (store, harness) => {
				const clock = declared(harness.clock, "clock");
				const { sid } = await opened(store, harness, "expired-join");
				await clock.advance(HOUR - 1);
				assert.equal(await store.join(sid, participant("rp", "client-1")), "joined");
				await clock.advance(1);
				assert.equal(await store.join(sid, participant("rp", "client-2")), "closed");
				const before = await store.live(sid);
				assert.equal(
					await store.open(sid, "user-1", before.value.expiresAt),
					"refused",
					"a repeated open from the session's end on is refused",
				);
				const read = await store.live(sid);
				assert.deepStrictEqual(read, before, "and writes nothing");
				assert.equal(read.value.state, "active");
				assert.deepStrictEqual(read.value.participants, [participant("rp", "client-1")]);
				const answer = committed(await store.close(sid, request({ cause: "expiry" })));
				assert.equal(answer.outcome, "closing", "a session past its end is still closed");
			}),
			test("a closing record is kept until the later of expiresAt plus the clock skew and the commit plus retainMs, then lapses whole", async (store, harness) => {
				const clock = declared(harness.clock, "clock");
				for (const retainMs of [10 * HOUR, 1]) {
					const { sid } = await opened(store, harness, `retention-${retainMs}`);
					const start = nowOf(harness);
					assert.equal(await store.join(sid, participant("rp", "client-1")), "joined");
					await clock.advance(HOUR / 2);
					const answer = committed(await store.close(sid, request({ retainMs })));
					const commit = answer.record.close?.closingAt.getTime() ?? Number.NaN;
					const until = Math.max(start + HOUR + DEFAULT_CLOCK_SKEW_MS, commit + retainMs);
					await clock.advance(until - nowOf(harness) - 1);
					const kept = await store.live(sid);
					assert.equal(kept.value.state, "closing", `retainMs ${retainMs}: kept`);
					assert.ok((await store.listClosing(1000)).includes(sid));
					await clock.advance(1);
					assert.equal(await store.read(sid), null, `retainMs ${retainMs}: lapsed`);
					assert.equal(await store.join(sid, participant("rp", "client-2")), "missing");
					assert.ok(!(await store.listClosing(1000)).includes(sid));
				}
			}),
		);
	} else {
		cases.push(notRun("the clock cases", "clock"));
	}

	if (input.supports?.forceExpire === true) {
		cases.push(
			test("retention lapses together: past it, an active, a closing and a closed record are each gone whole, and no part of one comes back", async (store, harness) => {
				const forceExpire = declared(harness.forceExpire, "forceExpire");
				const records: Array<{ sid: string; expiresAt: Date; generation: StoreGeneration }> = [];
				for (const state of ["active", "closing", "closed"] as const) {
					const { sid, expiresAt } = await opened(store, harness, `lapse-${state}`);
					assert.equal(await store.join(sid, participant("rp", "client-1")), "joined");
					assert.equal(await store.join(sid, participant("family", "fam-1")), "joined");
					if (state !== "active") {
						const answer = committed(await store.close(sid, request({ perParticipant: [] })));
						if (state === "closed") {
							assert.equal(
								(await store.complete(sid, answer.generation, "user_session")).outcome,
								"updated",
							);
						}
					}
					const read = await store.live(sid);
					assert.equal(read.value.state, state);
					records.push({ sid, expiresAt, generation: read.generation });
				}
				for (const { sid } of records) await forceExpire(sid);
				const listed = await store.listClosing(1000);
				for (const { sid, expiresAt, generation } of records) {
					assert.equal(await store.read(sid), null, `${sid}: gone`);
					assert.ok(!listed.includes(sid), `${sid}: not listed`);
					assert.equal(
						await store.join(sid, participant("rp", "client-2")),
						"missing",
						`${sid}: join`,
					);
					assert.equal((await store.close(sid)).outcome, "missing", `${sid}: close`);
					assert.equal(
						(await store.complete(sid, generation, "user_session")).outcome,
						"missing",
						`${sid}: completion`,
					);
					assert.equal(
						await store.open(sid, "user-1", expiresAt),
						"refused",
						`${sid}: not opened again`,
					);
					assert.equal(await store.read(sid), null, `${sid}: still gone`);
				}
			}),
		);
	} else {
		cases.push(notRun("the retention case", "forceExpire"));
	}

	if (input.supports?.unreachable === true) {
		cases.push(
			test("an outage rejects every member, never answering missing, null, closed or refused", async (_store, harness) => {
				const down = declared(harness.unreachable, "unreachable")();
				const sid = freshSid("outage");
				const calls: ReadonlyArray<readonly [string, () => Promise<unknown>]> = [
					["open", () => down.open(sid, "user-1", later(harness))],
					["join", () => down.join(sid, participant("rp", "client-1"))],
					["beginClose", () => down.beginClose(sid, request())],
					["completeIf", () => down.completeIf(sid, "g" as StoreGeneration, "user_session")],
					["read", () => down.read(sid)],
					["listClosing", () => down.listClosing(5)],
				];
				for (const [name, call] of calls) {
					await assert.rejects(call(), `${name} rejects`);
				}
			}),
		);
	} else {
		cases.push(notRun("the outage case", "unreachable"));
	}

	return cases;
}
