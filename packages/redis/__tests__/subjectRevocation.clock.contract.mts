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
 * What every `SubjectRevocation` adapter owes on its own clock: a boundary
 * later than the store's clock plus `DEFAULT_CLOCK_SKEW_MS` is recorded as
 * that clock plus the skew, never refused; one within it, or behind the
 * store's clock however far, is recorded as given.
 */

import {
	DEFAULT_CLOCK_SKEW_MS,
	type SubjectRevocation,
	type SupportsSessionsOnlyRevocation,
	supportsSessionsOnlyRevocation,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

/** The clock the store judges a boundary by. A store whose clock is a server passes a clock that reads it. */
export interface StoreClock {
	/** Epoch milliseconds on the store's clock. */
	now(): Promise<number>;
}

const hostClock: StoreClock = { now: async () => Date.now() };

/**
 * Margin on either side of the bound, wide enough that the store reading its
 * clock after the test did cannot move a case across it.
 */
const MARGIN_MS = 60_000;

const lifetime = async (clock: StoreClock): Promise<Date> =>
	new Date((await clock.now()) + 600_000);

/** The store's clock read just before and just after a write, the boundary asked for, and what reads back. */
interface ClampedWrite {
	readonly from: number;
	readonly to: number;
	readonly asked: number;
	readonly recorded: number | undefined;
}

/**
 * Writes a boundary past the bound through `write` and answers what `read`
 * says, with the store's clock read just before and just after the write: the
 * clamp lies between the two, plus the skew.
 */
const clampedWrite = async (
	clock: StoreClock,
	write: (before: Date, expiresAt: Date) => Promise<void>,
	read: () => Promise<Date | null>,
): Promise<ClampedWrite> => {
	const until = await lifetime(clock);
	const from = await clock.now();
	const asked = new Date(from + DEFAULT_CLOCK_SKEW_MS + MARGIN_MS);
	await write(asked, until);
	const to = await clock.now();
	const recorded = (await read())?.getTime();
	return { from, to, asked: asked.getTime(), recorded };
};

const expectClamped = (w: ClampedWrite): void => {
	expect(w.recorded).toBeDefined();
	expect(w.recorded as number).toBeGreaterThanOrEqual(w.from + DEFAULT_CLOCK_SKEW_MS);
	expect(w.recorded as number).toBeLessThanOrEqual(w.to + DEFAULT_CLOCK_SKEW_MS);
	expect(w.recorded as number).toBeLessThan(w.asked);
};

/** The base port's boundary on the store's clock: `revokeBefore` and `revokedBefore` only. */
export function runSubjectRevocationClockContract(
	factory: () => Promise<SubjectRevocation>,
	options: { readonly clock?: StoreClock } = {},
): void {
	const clock = options.clock ?? hostClock;

	describe("SubjectRevocation contract: the boundary on the store's clock", () => {
		it("records a boundary past the store's clock plus the skew as that clock plus the skew", async () => {
			const store = await factory();
			expectClamped(
				await clampedWrite(
					clock,
					(before, until) => store.revokeBefore("k-u1", before, until),
					() => store.revokedBefore("k-u1"),
				),
			);
		});

		it("records a boundary ahead of the store's clock by less than the skew as given", async () => {
			const store = await factory();
			const within = new Date((await clock.now()) + DEFAULT_CLOCK_SKEW_MS - MARGIN_MS);
			await store.revokeBefore("k-u2", within, await lifetime(clock));
			expect((await store.revokedBefore("k-u2"))?.getTime()).toBe(within.getTime());
		});

		it("records a boundary far behind the store's clock as given: a replica running behind still revokes", async () => {
			const store = await factory();
			const behind = new Date((await clock.now()) - DEFAULT_CLOCK_SKEW_MS - MARGIN_MS);
			await store.revokeBefore("k-u3", behind, await lifetime(clock));
			expect((await store.revokedBefore("k-u3"))?.getTime()).toBe(behind.getTime());
		});

		it("keeps a later boundary in force over an earlier one", async () => {
			const store = await factory();
			const within = new Date((await clock.now()) + DEFAULT_CLOCK_SKEW_MS - MARGIN_MS / 2);
			await store.revokeBefore("k-u4", within, await lifetime(clock));
			const behind = new Date((await clock.now()) - MARGIN_MS);
			await store.revokeBefore("k-u4", behind, await lifetime(clock));
			expect((await store.revokedBefore("k-u4"))?.getTime()).toBe(within.getTime());
		});

		it.each([
			["an Invalid Date", new Date(Number.NaN)],
			["an object that only answers getTime", { getTime: () => Number.NEGATIVE_INFINITY }],
		])(
			"refuses %s as before or expiresAt with a RangeError, leaving the boundary in force",
			async (_label, bad) => {
				const store = await factory();
				const held = new Date((await clock.now()) - MARGIN_MS);
				await store.revokeBefore("k-u8", held, await lifetime(clock));
				const notADate = bad as unknown as Date;
				await expect(store.revokeBefore("k-u8", notADate, await lifetime(clock))).rejects.toThrow(
					RangeError,
				);
				await expect(store.revokeBefore("k-u8", new Date(), notADate)).rejects.toThrow(RangeError);
				expect((await store.revokedBefore("k-u8"))?.getTime()).toBe(held.getTime());
			},
		);
	});
}

/**
 * The second boundary on the store's clock, for a store that claims
 * `SupportsSessionsOnlyRevocation`: `revokeBefore` clamps the grants boundary
 * with the sessions one, and `revokeSessionsBefore` clamps the sessions
 * boundary alone, leaving the grants boundary as it was.
 */
export function runSessionsOnlyRevocationClockContract(
	factory: () => Promise<SubjectRevocation>,
	options: { readonly clock?: StoreClock } = {},
): void {
	const clock = options.clock ?? hostClock;
	const capable = async (): Promise<SubjectRevocation & SupportsSessionsOnlyRevocation> => {
		const store = await factory();
		if (!supportsSessionsOnlyRevocation(store)) {
			throw new Error("this adapter does not claim SupportsSessionsOnlyRevocation");
		}
		return store;
	};

	describe("SupportsSessionsOnlyRevocation contract: the boundary on the store's clock", () => {
		it("clamps the grants boundary with the sessions one on a full revocation", async () => {
			const store = await capable();
			const w = await clampedWrite(
				clock,
				(before, until) => store.revokeBefore("k-u5", before, until),
				() => store.revokedBefore("k-u5"),
			);
			expectClamped(w);
			expect((await store.grantsRevokedBefore("k-u5"))?.getTime()).toBe(w.recorded);
		});

		it("records a sessions boundary past the store's clock plus the skew as that clock plus the skew, leaving grants as they were", async () => {
			const store = await capable();
			expectClamped(
				await clampedWrite(
					clock,
					(before, until) => store.revokeSessionsBefore("k-u6", before, until),
					() => store.revokedBefore("k-u6"),
				),
			);
			expect(await store.grantsRevokedBefore("k-u6")).toBeNull();
		});

		it("records a sessions boundary within the skew, and one far behind, as given", async () => {
			const store = await capable();
			const behind = new Date((await clock.now()) - DEFAULT_CLOCK_SKEW_MS - MARGIN_MS);
			await store.revokeSessionsBefore("k-u7", behind, await lifetime(clock));
			expect((await store.revokedBefore("k-u7"))?.getTime()).toBe(behind.getTime());
			const within = new Date((await clock.now()) + DEFAULT_CLOCK_SKEW_MS - MARGIN_MS);
			await store.revokeSessionsBefore("k-u7", within, await lifetime(clock));
			expect((await store.revokedBefore("k-u7"))?.getTime()).toBe(within.getTime());
		});
	});
}
