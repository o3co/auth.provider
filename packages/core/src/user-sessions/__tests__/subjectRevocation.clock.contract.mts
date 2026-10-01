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
 * later than the store's clock plus `DEFAULT_CLOCK_SKEW_MS` is refused with a
 * `RangeError` and nothing is written; one behind the store's clock is not.
 */

import { describe, expect, it } from "vitest";
import { DEFAULT_CLOCK_SKEW_MS } from "../../jwt/verify.mjs";
import {
	type SubjectRevocation,
	type SupportsSessionsOnlyRevocation,
	supportsSessionsOnlyRevocation,
} from "../types.mjs";

/** The clock the store judges a boundary by. A Redis runner reads the server's `TIME`. */
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

export function runSubjectRevocationClockContract(
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

	describe("SubjectRevocation contract: the boundary on the store's clock", () => {
		it("refuses a boundary past the store's clock plus the skew, writing nothing", async () => {
			const store = await factory();
			const ahead = new Date((await clock.now()) + DEFAULT_CLOCK_SKEW_MS + MARGIN_MS);
			await expect(store.revokeBefore("k-u1", ahead, await lifetime(clock))).rejects.toThrow(
				RangeError,
			);
			expect(await store.revokedBefore("k-u1")).toBeNull();
		});

		it("leaves a boundary in force as it was when it refuses a later one", async () => {
			const store = await capable();
			const held = new Date((await clock.now()) - MARGIN_MS);
			await store.revokeBefore("k-u2", held, await lifetime(clock));
			const ahead = new Date((await clock.now()) + DEFAULT_CLOCK_SKEW_MS + MARGIN_MS);
			await expect(store.revokeBefore("k-u2", ahead, await lifetime(clock))).rejects.toThrow(
				RangeError,
			);
			expect((await store.revokedBefore("k-u2"))?.getTime()).toBe(held.getTime());
			expect((await store.grantsRevokedBefore("k-u2"))?.getTime()).toBe(held.getTime());
		});

		it("records a boundary ahead of the store's clock by less than the skew", async () => {
			const store = await factory();
			const within = new Date((await clock.now()) + DEFAULT_CLOCK_SKEW_MS - MARGIN_MS);
			await store.revokeBefore("k-u3", within, await lifetime(clock));
			expect((await store.revokedBefore("k-u3"))?.getTime()).toBe(within.getTime());
		});

		it("records a boundary far behind the store's clock: a replica running behind still revokes", async () => {
			const store = await factory();
			const behind = new Date((await clock.now()) - DEFAULT_CLOCK_SKEW_MS - MARGIN_MS);
			await store.revokeBefore("k-u4", behind, await lifetime(clock));
			expect((await store.revokedBefore("k-u4"))?.getTime()).toBe(behind.getTime());
		});
	});

	describe("SupportsSessionsOnlyRevocation contract: the boundary on the store's clock", () => {
		it("refuses a sessions boundary past the store's clock plus the skew, writing nothing", async () => {
			const store = await capable();
			const held = new Date((await clock.now()) - MARGIN_MS);
			await store.revokeSessionsBefore("k-u5", held, await lifetime(clock));
			const ahead = new Date((await clock.now()) + DEFAULT_CLOCK_SKEW_MS + MARGIN_MS);
			await expect(
				store.revokeSessionsBefore("k-u5", ahead, await lifetime(clock)),
			).rejects.toThrow(RangeError);
			expect((await store.revokedBefore("k-u5"))?.getTime()).toBe(held.getTime());
			expect(await store.grantsRevokedBefore("k-u5")).toBeNull();
		});

		it("records a sessions boundary within the skew, and one far behind", async () => {
			const store = await capable();
			const behind = new Date((await clock.now()) - DEFAULT_CLOCK_SKEW_MS - MARGIN_MS);
			await store.revokeSessionsBefore("k-u6", behind, await lifetime(clock));
			expect((await store.revokedBefore("k-u6"))?.getTime()).toBe(behind.getTime());
			const within = new Date((await clock.now()) + DEFAULT_CLOCK_SKEW_MS - MARGIN_MS);
			await store.revokeSessionsBefore("k-u6", within, await lifetime(clock));
			expect((await store.revokedBefore("k-u6"))?.getTime()).toBe(within.getTime());
		});
	});
}
