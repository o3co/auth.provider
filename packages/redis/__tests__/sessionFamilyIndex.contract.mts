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

import {
	DEFAULT_CLOCK_SKEW_MS,
	type SessionFamilyIndex,
	type SupportsSessionEnd,
	supportsSessionEnd,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

export type SessionFamilyIndexFactory = () => Promise<SessionFamilyIndex>;

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

/**
 * How a test reaches an entry's expiry on the store's own terms. An
 * in-process store judges expiry on this process's clock. A Redis key expires
 * on the server's, which sits to either side of the host's, and a relative
 * `PX` runs from when the command reached the server; a loaded run also
 * reaches its next line late. So a fixed sleep after a short expiry may read
 * an entry the store has already dropped, or one it has not dropped yet. The
 * default is this process's clock; a Redis runner passes one that reads the
 * server's `TIME`, or waits for the keys to be gone.
 */
export interface ExpiryClock {
	/** Epoch milliseconds on the clock the store expires entries by. */
	now(): Promise<number>;
	/** Resolves once the store has let everything expiring at `at` go. */
	passed(at: Date): Promise<void>;
}

const hostExpiry: ExpiryClock = {
	now: async () => Date.now(),
	passed: async (at) => {
		while (Date.now() <= at.getTime()) {
			await new Promise((r) => setTimeout(r, at.getTime() - Date.now() + 1));
		}
	},
};

/**
 * An expiry a second ahead of whichever clock is later — the host's, which a
 * write checks it against, and the store's, which expires it — so a read that
 * follows the write lands well inside it however loaded the run is.
 */
const aheadOf = async (clock: ExpiryClock): Promise<Date> =>
	new Date(Math.max(Date.now(), await clock.now()) + 1_000);

export function runSessionFamilyIndexContract(
	factory: SessionFamilyIndexFactory,
	options: { readonly expiry?: ExpiryClock } = {},
): void {
	describe("SessionFamilyIndex contract", () => {
		const expiry = options.expiry ?? hostExpiry;

		it("addFamilyId then listFamilyIds returns the id", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toHaveLength(1);
			expect(list[0]).toBe("fam-A");
		});

		it("addFamilyId is idempotent on duplicate familyId", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toHaveLength(1);
			expect(list[0]).toBe("fam-A");
		});

		it("distinct ids accumulate in insertion order", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			await idx.addFamilyId("sid-1", "fam-B", FUTURE());
			await idx.addFamilyId("sid-1", "fam-C", FUTURE());
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toEqual(["fam-A", "fam-B", "fam-C"]);
		});

		it("listFamilyIds returns empty array for unknown sid", async () => {
			const idx = await factory();
			const list = await idx.listFamilyIds("ghost");
			expect(list).toEqual([]);
		});

		it("addFamilyId after past expiresAt is a no-op", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", PAST());
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toEqual([]);
		});

		it("addFamilyId refuses an expiresAt that is not a valid date, and records nothing", async () => {
			// An Invalid Date's time is NaN, which is never `<= now`: the memory
			// store would keep such an entry for ever, and Redis would write the
			// entry, then refuse `PEXPIREAT NaN` and leave the key with no TTL.
			// A caller fault.
			const idx = await factory();
			await expect(idx.addFamilyId("sid-1", "fam-A", new Date(Number.NaN))).rejects.toThrow(
				RangeError,
			);
			expect(await idx.listFamilyIds("sid-1")).toEqual([]);
		});

		it("listFamilyIds returns empty after expiresAt elapsed", async () => {
			// Dated from, and waited out on, the store's own clock (see
			// `ExpiryClock`).
			const idx = await factory();
			const expiresAt = await aheadOf(expiry);
			await idx.addFamilyId("sid-1", "fam-A", expiresAt);
			expect(await idx.listFamilyIds("sid-1")).toHaveLength(1);
			await expiry.passed(expiresAt);
			expect(await idx.listFamilyIds("sid-1")).toEqual([]);
		});

		it("removeBySid clears all family ids for the sid", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			await idx.addFamilyId("sid-1", "fam-B", FUTURE());
			await idx.removeBySid("sid-1");
			const list = await idx.listFamilyIds("sid-1");
			expect(list).toEqual([]);
		});

		it("removeBySid is idempotent on absent sid", async () => {
			const idx = await factory();
			await expect(idx.removeBySid("ghost")).resolves.toBeUndefined();
		});

		it("listFamilyIds returns a defensive copy (caller mutation isolated)", async () => {
			const idx = await factory();
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
			await idx.addFamilyId("sid-1", "fam-B", FUTURE());
			const list = await idx.listFamilyIds("sid-1");
			(list as string[]).push("evil");
			expect(await idx.listFamilyIds("sid-1")).toEqual(["fam-A", "fam-B"]);
		});

		it("readonly kind field present", async () => {
			const idx = await factory();
			expect(typeof idx.kind).toBe("string");
			expect(idx.kind.length).toBeGreaterThan(0);
		});
	});
}

/**
 * What an index owes once it claims {@link SupportsSessionEnd}: for an add
 * and an end on the same sid, the end lists the family or the add answers
 * `"ended"`. Optional on the port, so the suite above does not ask for it,
 * and this one runs only against an index that claims it.
 */
export function runSessionEndContract(
	factory: SessionFamilyIndexFactory,
	options: { readonly expiry?: ExpiryClock } = {},
): void {
	const expiry = options.expiry ?? hostExpiry;
	const capable = async (): Promise<SessionFamilyIndex & SupportsSessionEnd> => {
		const idx = await factory();
		if (!supportsSessionEnd(idx)) {
			throw new Error("this adapter does not claim SupportsSessionEnd");
		}
		return idx;
	};
	/** The guarantee, for one add and one end on the same sid. */
	const listedOrEnded = (
		listed: ReadonlyArray<string>,
		answer: "added" | "ended",
		familyId: string,
	): void => {
		expect(
			listed.includes(familyId) || answer === "ended",
			`the end listed ${JSON.stringify(listed)} and the add answered "${answer}"`,
		).toBe(true);
	};

	describe("SupportsSessionEnd contract — endSession and addFamilyIdUnlessEnded", () => {
		it("an add before the end is added, and the end lists its family", async () => {
			const idx = await capable();
			const expiresAt = FUTURE();
			expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt)).toBe("added");
			expect(await idx.endSession("sid-1", expiresAt)).toEqual(["fam-A"]);
		});

		it("an add after the end answers ended", async () => {
			const idx = await capable();
			const expiresAt = FUTURE();
			expect(await idx.endSession("sid-1", expiresAt)).toEqual([]);
			expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt)).toBe("ended");
		});

		it("an end and an add started together (end first): the end lists the family, or the add answers ended", async () => {
			// Neither is awaited before the other starts; however the store orders
			// the two, one of them sees the other.
			const idx = await capable();
			const expiresAt = FUTURE();
			const ending = idx.endSession("sid-1", expiresAt);
			const adding = idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt);
			const [listed, answer] = await Promise.all([ending, adding]);
			listedOrEnded(listed, answer, "fam-A");
		});

		it("an end and an add started together (add first): the end lists the family, or the add answers ended", async () => {
			const idx = await capable();
			const expiresAt = FUTURE();
			const adding = idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt);
			const ending = idx.endSession("sid-1", expiresAt);
			const [answer, listed] = await Promise.all([adding, ending]);
			listedOrEnded(listed, answer, "fam-A");
		});

		it("removeBySid keeps the mark: an add after it still answers ended", async () => {
			const idx = await capable();
			const expiresAt = FUTURE();
			await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt);
			await idx.endSession("sid-1", expiresAt);
			await idx.removeBySid("sid-1");
			expect(await idx.listFamilyIds("sid-1")).toEqual([]);
			expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-B", expiresAt)).toBe("ended");
		});

		it("an end marks the session even past expiresAt, and the mark lapses once the clock-skew allowance after it has passed", async () => {
			// The session's life is placed so that the allowance after it ends a
			// second ahead on the store's clock (see `ExpiryClock`). The adds stand
			// for a session that reuses the sid, so they carry an expiry of their
			// own.
			const idx = await capable();
			const markLapses = await aheadOf(expiry);
			const expiresAt = new Date(markLapses.getTime() - DEFAULT_CLOCK_SKEW_MS);
			await idx.endSession("sid-1", expiresAt);
			expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", FUTURE())).toBe("ended");
			await expiry.passed(markLapses);
			expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-B", FUTURE())).toBe("added");
		});

		it("endSession is idempotent: a retry lists the same families, and the mark holds", async () => {
			const idx = await capable();
			const expiresAt = FUTURE();
			await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt);
			await idx.addFamilyIdUnlessEnded("sid-1", "fam-B", expiresAt);
			const first = await idx.endSession("sid-1", expiresAt);
			const retry = await idx.endSession("sid-1", expiresAt);
			expect(first).toEqual(["fam-A", "fam-B"]);
			expect(retry).toEqual(first);
			expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-C", expiresAt)).toBe("ended");
		});

		it("the mark is the sid's alone: another sid's add is added", async () => {
			const idx = await capable();
			await idx.endSession("sid-1", FUTURE());
			expect(await idx.addFamilyIdUnlessEnded("sid-2", "fam-A", FUTURE())).toBe("added");
			expect(await idx.listFamilyIds("sid-2")).toEqual(["fam-A"]);
		});

		it("an add past expiresAt answers ended and records nothing", async () => {
			const idx = await capable();
			expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", PAST())).toBe("ended");
			expect(await idx.listFamilyIds("sid-1")).toEqual([]);
		});

		it("endSession refuses an expiresAt that is not a valid date, and writes no mark", async () => {
			const idx = await capable();
			await expect(idx.endSession("sid-1", new Date(Number.NaN))).rejects.toThrow(RangeError);
			expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", FUTURE())).toBe("added");
		});

		it("addFamilyIdUnlessEnded refuses an expiresAt that is not a valid date, and records nothing", async () => {
			const idx = await capable();
			await expect(
				idx.addFamilyIdUnlessEnded("sid-1", "fam-A", new Date(Number.NaN)),
			).rejects.toThrow(RangeError);
			expect(await idx.listFamilyIds("sid-1")).toEqual([]);
		});
	});
}
