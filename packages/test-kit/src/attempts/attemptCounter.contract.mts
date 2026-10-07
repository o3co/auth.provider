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
 * The contract suite of core's `AttemptCounter` port, the counter behind a
 * verifier's own attempt limits: a fixed window per key that allows exactly
 * the first `limit` attempts, against the spec handed in with each attempt,
 * a lowered or raised limit applying at once, a shortened or lengthened
 * window keeping a running window's end, and a refused attempt counting nothing; keys counted apart; remaining and the window's end answered right;
 * concurrent attempts counted exactly; a key or spec it cannot count
 * rejected, counting nothing; and, declared, an outage rejected rather than
 * answered as a count. Every answer is read through core's
 * `readAttemptCount`, the reading the attempt guard applies.
 *
 * Each case builds a fresh harness, counts under keys of its own, and closes
 * it. With no `clock`, the window cases wait out a one-second window in real
 * time, and a window's end is judged within {@link REAL_CLOCK_TOLERANCE_MS}.
 */

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
	type AttemptCount,
	type AttemptCounter,
	type AttemptSpec,
	readAttemptCount,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";

/** What one case runs over. */
export interface AttemptCounterHarness {
	readonly counter: AttemptCounter;
	/**
	 * The same backend through a second instance: another connection, pool or
	 * client. Absent: `counter` again, with no cross-process proof.
	 */
	readonly second?: AttemptCounter;
	/**
	 * The counter's clock, which the harness moves by hand. Absent: the
	 * counter reads the real clock, and the window cases wait in real time.
	 */
	readonly clock?: {
		/** Epoch milliseconds, as the counter reads them. */
		now(): number;
		advance(ms: number): void | Promise<void>;
	};
	/** A counter over the same backend that cannot reach it. */
	readonly unreachable?: () => AttemptCounter;
	readonly close?: () => Promise<void>;
}

export interface AttemptCounterContractInput {
	readonly build: () => Promise<AttemptCounterHarness>;
	/**
	 * The hooks every harness `build` answers, declared up front, so the case
	 * list is fixed when the suite is built. A declared hook that a harness
	 * lacks fails its case; an undeclared one runs no case, and one passing
	 * case names what was not run.
	 */
	readonly supports?: {
		readonly unreachable?: boolean;
	};
}

/** How far a counter on the real clock may place a window's end from where the suite expects it. */
export const REAL_CLOCK_TOLERANCE_MS = 1_000;

/** A key no other case uses, on a backend cases may share. */
const freshKey = (label: string): string => `attempt-contract:${label}:${randomUUID()}`;

/** The epoch milliseconds the counter reads now. */
const nowOf = (harness: AttemptCounterHarness): number => harness.clock?.now() ?? Date.now();

/** Lets `ms` pass on the counter's clock. */
async function elapse(harness: AttemptCounterHarness, ms: number): Promise<void> {
	if (harness.clock !== undefined) {
		await harness.clock.advance(ms);
		return;
	}
	await new Promise((resolve) => setTimeout(resolve, ms));
}

/** One attempt, its answer read as the guard reads it, on the counter's clock. */
async function attempt(
	harness: AttemptCounterHarness,
	key: string,
	spec: AttemptSpec,
	counter: AttemptCounter = harness.counter,
): Promise<AttemptCount> {
	const answer: unknown = await counter.consume(key, spec);
	const read = readAttemptCount(answer, spec, nowOf(harness));
	assert.ok(
		read !== undefined,
		`consume(${key}) answered ${String(answer)}, which is not a count under ${JSON.stringify(spec)}`,
	);
	return read;
}

/** Throws unless `resetAt` is `windowSeconds` after an instant in [from, to]. */
function assertWindowEnd(
	harness: AttemptCounterHarness,
	resetAt: Date,
	from: number,
	to: number,
	windowSeconds: number,
): void {
	const tolerance = harness.clock === undefined ? REAL_CLOCK_TOLERANCE_MS : 0;
	const at = resetAt.getTime();
	const earliest = from + windowSeconds * 1000 - tolerance;
	const latest = to + windowSeconds * 1000 + tolerance;
	assert.ok(
		at >= earliest && at <= latest,
		`resetAt ${resetAt.toISOString()} is not ${windowSeconds}s after the window's first attempt`,
	);
}

const BAD_KEYS: readonly unknown[] = ["", "k".repeat(513), undefined, null, 7, {}];

const BAD_SPECS: readonly unknown[] = [
	undefined,
	null,
	{ windowSeconds: 60 },
	{ limit: 2 },
	{ limit: 0, windowSeconds: 60 },
	{ limit: -1, windowSeconds: 60 },
	{ limit: 1.5, windowSeconds: 60 },
	{ limit: Number.NaN, windowSeconds: 60 },
	{ limit: "2", windowSeconds: 60 },
	{ limit: 2, windowSeconds: 0 },
	{ limit: 2, windowSeconds: 0.5 },
	{ limit: 2, windowSeconds: Number.POSITIVE_INFINITY },
	{ limit: 2, windowSeconds: 86_401 },
];

const shown = (value: unknown): string =>
	value === undefined
		? "undefined"
		: typeof value === "number" && !Number.isFinite(value)
			? String(value)
			: JSON.stringify(value);

/** The cases of the `AttemptCounter` contract over the harnesses `input` builds. */
export function attemptCounterContract(
	input: AttemptCounterContractInput,
): readonly ContractCase[] {
	const test = (
		name: string,
		body: (harness: AttemptCounterHarness) => Promise<void>,
	): ContractCase => ({
		name,
		run: async () => {
			const harness = await input.build();
			try {
				await body(harness);
			} finally {
				await harness.close?.();
			}
		},
	});

	const cases: ContractCase[] = [
		test("allows limit attempts in a window and refuses the rest, remaining counting down to 0, every answer naming the window's end", async (harness) => {
			const spec: AttemptSpec = { limit: 3, windowSeconds: 60 };
			const key = freshKey("window");
			const from = nowOf(harness);
			const answers: AttemptCount[] = [];
			for (let i = 0; i < 5; i++) answers.push(await attempt(harness, key, spec));
			const to = nowOf(harness);
			assert.deepEqual(
				answers.map((a) => [a.allowed, a.remaining]),
				[
					[true, 2],
					[true, 1],
					[true, 0],
					[false, 0],
					[false, 0],
				],
				"a limit of 3 allows three attempts, remaining 2, 1, 0, and refuses the rest",
			);
			const first = answers[0] as AttemptCount;
			assertWindowEnd(harness, first.resetAt, from, to, spec.windowSeconds);
			for (const answer of answers) {
				assert.equal(
					answer.resetAt.getTime(),
					first.resetAt.getTime(),
					"every attempt in a window, refused ones included, names the same end",
				);
			}
		}),

		test("a window ends windowSeconds after its first attempt, and the next attempt starts another", async (harness) => {
			const spec: AttemptSpec = { limit: 1, windowSeconds: 1 };
			const key = freshKey("reset");
			const first = await attempt(harness, key, spec);
			assert.equal(first.allowed, true);
			assert.equal((await attempt(harness, key, spec)).allowed, false);
			if (harness.clock !== undefined) {
				await elapse(harness, 999);
				assert.equal(
					(await attempt(harness, key, spec)).allowed,
					false,
					"the window has not ended a millisecond before its end",
				);
				await elapse(harness, 1);
			} else {
				await elapse(harness, 1_000 + REAL_CLOCK_TOLERANCE_MS / 2);
			}
			const from = nowOf(harness);
			const next = await attempt(harness, key, spec);
			const to = nowOf(harness);
			assert.deepEqual(
				[next.allowed, next.remaining],
				[true, 0],
				"the first attempt after the window's end starts another",
			);
			assert.ok(next.resetAt.getTime() > first.resetAt.getTime());
			assertWindowEnd(harness, next.resetAt, from, to, spec.windowSeconds);
		}),

		test("keys are counted apart", async (harness) => {
			const spec: AttemptSpec = { limit: 2, windowSeconds: 60 };
			const base = freshKey("keys");
			const spent = `${base}:ip:192.0.2.1`;
			for (let i = 0; i < 3; i++) await attempt(harness, spent, spec);
			for (const other of [
				`${base}:ip:192.0.2.2`,
				`${base}:user:192.0.2.1`,
				`${base}:ip`,
				base,
				`${spent}:x`,
				`${base}:__proto__`,
				`${base}:constructor`,
			]) {
				const answer = await attempt(harness, other, spec);
				assert.deepEqual(
					[answer.allowed, answer.remaining],
					[true, 1],
					`${other} is counted apart from ${spent}`,
				);
			}
			assert.equal((await attempt(harness, spent, spec)).allowed, false, `${spent} is still spent`);
		}),

		test("each key is counted against the spec handed in with its attempt", async (harness) => {
			for (const limit of [1, 2, 5]) {
				const spec: AttemptSpec = { limit, windowSeconds: 60 };
				const key = freshKey(`spec-${limit}`);
				const allowed: boolean[] = [];
				for (let i = 0; i <= limit; i++) {
					allowed.push((await attempt(harness, key, spec)).allowed);
				}
				assert.deepEqual(
					allowed,
					[...Array.from({ length: limit }, () => true), false],
					`a limit of ${limit} handed in allows ${limit} attempts and refuses the next`,
				);
			}
		}),

		test("a window shortened on a live key keeps its end: window 60, then window 1, answers the same resetAt", async (harness) => {
			const key = freshKey("shortened");
			const first = await attempt(harness, key, { limit: 5, windowSeconds: 60 });
			const second = await attempt(harness, key, { limit: 5, windowSeconds: 1 });
			assert.deepEqual([second.allowed, second.remaining], [true, 3]);
			assert.equal(
				second.resetAt.getTime(),
				first.resetAt.getTime(),
				"a spec's window applies when a window starts, never to one already running",
			);
		}),

		test("a window lengthened on a live key keeps its end: window 1, then window 60, answers the same resetAt", async (harness) => {
			const key = freshKey("lengthened");
			const first = await attempt(harness, key, { limit: 5, windowSeconds: 1 });
			const second = await attempt(harness, key, { limit: 5, windowSeconds: 60 });
			assert.deepEqual([second.allowed, second.remaining], [true, 3]);
			assert.equal(
				second.resetAt.getTime(),
				first.resetAt.getTime(),
				"a spec's window applies when a window starts, never to one already running",
			);
		}),

		test("concurrent attempts on one key are counted exactly, across instances", async (harness) => {
			const spec: AttemptSpec = { limit: 5, windowSeconds: 60 };
			const key = freshKey("concurrent");
			const counters = [harness.counter, harness.second ?? harness.counter];
			const answers = await Promise.all(
				Array.from({ length: 24 }, (_, i) =>
					attempt(harness, key, spec, counters[i % 2] as AttemptCounter),
				),
			);
			const allowed = answers.filter((a) => a.allowed);
			assert.equal(allowed.length, 5, `${allowed.length} of 24 concurrent attempts allowed, not 5`);
			assert.deepEqual(
				allowed.map((a) => a.remaining).sort((a, b) => a - b),
				[0, 1, 2, 3, 4],
				"each allowed attempt is answered its own remaining",
			);
		}),

		test("a key or spec it cannot count is rejected, and counts nothing", async (harness) => {
			const spec: AttemptSpec = { limit: 2, windowSeconds: 60 };
			const key = freshKey("bad-input");
			const consume = (k: unknown, s: unknown) =>
				Promise.resolve().then(() => harness.counter.consume(k as string, s as AttemptSpec));
			for (const bad of BAD_KEYS) {
				await assert.rejects(consume(bad, spec), `the key ${shown(bad)} is rejected`);
			}
			for (const bad of BAD_SPECS) {
				await assert.rejects(consume(key, bad), `the spec ${shown(bad)} is rejected`);
			}
			const first = await attempt(harness, key, spec);
			assert.deepEqual(
				[first.allowed, first.remaining],
				[true, 1],
				"a rejected attempt counted nothing under its key",
			);
			const longest = `${key}:${"k".repeat(512)}`.slice(0, 512);
			assert.equal(
				(await attempt(harness, longest, spec)).allowed,
				true,
				"a key of 512 characters is counted",
			);
		}),

		test("a limit lowered on a live key applies at once: limit 5, then limit 2, allows the second attempt with nothing remaining and refuses the third", async (harness) => {
			const key = freshKey("lowered");
			const wide: AttemptSpec = { limit: 5, windowSeconds: 60 };
			const narrow: AttemptSpec = { limit: 2, windowSeconds: 60 };
			const answers = [
				await attempt(harness, key, wide),
				await attempt(harness, key, narrow),
				await attempt(harness, key, narrow),
			];
			assert.deepEqual(
				answers.map((a) => [a.allowed, a.remaining]),
				[
					[true, 4],
					[true, 0],
					[false, 0],
				],
			);
		}),

		test("a limit raised on a live key applies at once, and the refused attempts counted nothing: limit 2 spent, then limit 5, allows the next attempt with 2 remaining", async (harness) => {
			const key = freshKey("raised");
			const narrow: AttemptSpec = { limit: 2, windowSeconds: 60 };
			const wide: AttemptSpec = { limit: 5, windowSeconds: 60 };
			const answers = [
				await attempt(harness, key, narrow),
				await attempt(harness, key, narrow),
				await attempt(harness, key, narrow),
				await attempt(harness, key, narrow),
				await attempt(harness, key, wide),
			];
			assert.deepEqual(
				answers.map((a) => [a.allowed, a.remaining]),
				[
					[true, 1],
					[true, 0],
					[false, 0],
					[false, 0],
					[true, 2],
				],
			);
		}),
	];

	if (input.supports?.unreachable === true) {
		cases.push(
			test("a counter that cannot reach its backend rejects, never answering a count", async (harness) => {
				assert.ok(
					harness.unreachable !== undefined,
					"supports.unreachable is declared, but the harness has no unreachable",
				);
				await assert.rejects(
					Promise.resolve().then(() =>
						harness.unreachable?.().consume(freshKey("outage"), { limit: 5, windowSeconds: 60 }),
					),
					"an outage must reject: answered as a count, it would lift the limit",
				);
			}),
		);
	} else {
		cases.push({
			name: "not run: the outage case (supports.unreachable not declared)",
			run: async () => {},
		});
	}
	return cases;
}
