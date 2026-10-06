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
 * When a stamping takes a write as settled, and what the boundary it leaves
 * covers: every token minted before that write committed, by an issuer up to
 * the verification allowance ahead of the writer's clock.
 */

import { describe, expect, it } from "vitest";
import {
	claimCoveredByRevocationBoundary,
	DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
} from "#/jwt/verify.mjs";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { stampSubjectBoundary } from "#/user-sessions/stampSubjectBoundary.mjs";

const TTL = 3_600_000;
/** A whole second. */
const T0 = 1_790_000_000_000;

/**
 * A wall clock and a monotonic clock the test moves. Each write moves them by
 * the next of `steps` (the last for every later write) and records the
 * instant it was handed.
 */
const harness = (
	startMs: number,
	steps: ReadonlyArray<{ readonly wall: number; readonly monotonic: number }>,
) => {
	let wall = startMs;
	let monotonic = 0;
	const store = createInMemorySubjectRevocation({ now: () => wall });
	const writes: number[] = [];
	const commits: number[] = [];
	const write = async (before: Date, expiresAt: Date): Promise<void> => {
		const step = steps[Math.min(writes.length, steps.length - 1)] ?? { wall: 0, monotonic: 0 };
		writes.push(before.getTime());
		wall += step.wall;
		monotonic += step.monotonic;
		await store.revokeBefore("user-1", before, expiresAt);
		commits.push(wall);
	};
	return { store, writes, commits, write, now: () => wall, elapsed: () => monotonic };
};

const slow = { wall: 5_000, monotonic: 5_000 };
const settling = { wall: 250, monotonic: 250 };
const instant = { wall: 0, monotonic: 0 };

describe("stampSubjectBoundary — what a settled write covers", () => {
	it.each([0, 100, 500, 899, 900, 950, 999])(
		"covers a token an issuer a full allowance ahead mints just before the settling write commits, the write sampled %i ms into a second",
		async (offset) => {
			// The second write is sampled `offset` ms into a second and takes the
			// whole settling bound to commit.
			const h = harness(T0 + offset - slow.wall, [slow, settling]);
			const stamped = await stampSubjectBoundary(h.write, h.now, TTL, h.elapsed);
			expect(stamped).toEqual({ written: true });
			expect(h.writes).toHaveLength(2);
			const committedAt = h.commits.at(-1) as number;
			const mintedIat = Math.floor((committedAt - 1 + DEFAULT_SUBJECT_REVOCATION_SKEW_MS) / 1000);
			expect(
				claimCoveredByRevocationBoundary(
					mintedIat,
					await h.store.revokedBefore("user-1"),
					DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
				),
			).toBe(true);
		},
	);
});

describe("stampSubjectBoundary — a write's commit time is measured on the monotonic clock", () => {
	it.each([
		["the monotonic clock read backwards", { wall: 0, monotonic: -1 }],
		["the wall clock jumped ahead across it", { wall: 5_000, monotonic: 0 }],
	] as const)("a second write is not settled when %s, and is stamped again", async (_, step) => {
		const h = harness(T0, [slow, step, { wall: 0, monotonic: 0 }]);
		const stamped = await stampSubjectBoundary(h.write, h.now, TTL, h.elapsed);
		expect(stamped).toEqual({ written: true });
		expect(h.writes).toHaveLength(3);
	});
});

describe("stampSubjectBoundary — a wall clock seen going back is a failure, whatever the later writes do", () => {
	it("an issuer mints during a slow second write, the wall clock then rolls back, and a third write settles at once", async () => {
		// Write 1 moves both clocks 5 s. During write 2 the wall clock reaches
		// T0 + 9999 ms, where an issuer mints, then rolls back 5 s: across the
		// write it reads no later than before, while 5 s passed. Write 3 is
		// instant.
		const h = harness(T0, [slow, { wall: 0, monotonic: 5_000 }, instant]);
		const mintedIat = Math.floor((T0 + 9_999) / 1000);
		const stamped = await stampSubjectBoundary(h.write, h.now, TTL, h.elapsed);
		expect(stamped).toEqual({ written: true, failure: { error: expect.any(Error), stamp: 2 } });
		// Why it is a failure: what the stamping left does not cover that token.
		expect(
			claimCoveredByRevocationBoundary(
				mintedIat,
				await h.store.revokedBefore("user-1"),
				DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
			),
		).toBe(false);
	});

	it.each([
		[
			"a write's wall reading is lower than the one before it",
			[slow, slow, { wall: -5_000, monotonic: 0 }, instant],
		],
		[
			"the wall clock stepped back across a write",
			[slow, { wall: -5_000, monotonic: 5_000 }, instant],
		],
		[
			"the wall clock fell behind the monotonic clock across a write",
			[slow, { wall: 0, monotonic: 5_000 }, instant],
		],
		[
			"the wall clock stepped back across the first write",
			[
				{ wall: -60_000, monotonic: 0 },
				{ wall: 0, monotonic: 0 },
			],
		],
	] as const)("reports the second stamp as failed when %s", async (_, steps) => {
		const h = harness(T0, steps);
		const stamped = await stampSubjectBoundary(h.write, h.now, TTL, h.elapsed);
		expect(stamped).toEqual({ written: true, failure: { error: expect.any(Error), stamp: 2 } });
	});
});
