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

import type { SessionFamilyIndex } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

export type SessionFamilyIndexFactory = () => Promise<SessionFamilyIndex>;

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

/**
 * How a test reaches an entry's expiry on the store's own terms.
 *
 * An in-process store judges expiry on this process's clock. A Redis key
 * expires on the server's, which sits to either side of the host's, and a
 * relative `PX` runs from when the command reached the server; a loaded run
 * also reaches its next line late. A fixed sleep after a short expiry therefore
 * either read an entry the store had already dropped, or checked one it had
 * not dropped yet. The default is this process's clock; a Redis runner passes
 * one that reads the server's `TIME`, or waits for the keys to be gone.
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
	expiry: ExpiryClock = hostExpiry,
): void {
	describe("SessionFamilyIndex contract", () => {
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
			// store kept such an entry for ever, and Redis wrote the entry and then
			// refused `PEXPIREAT NaN`, leaving the key with no TTL. A caller fault.
			const idx = await factory();
			await expect(idx.addFamilyId("sid-1", "fam-A", new Date(Number.NaN))).rejects.toThrow(
				RangeError,
			);
			expect(await idx.listFamilyIds("sid-1")).toEqual([]);
		});

		it("listFamilyIds returns empty after expiresAt elapsed", async () => {
			// Dated from, and waited out on, the store's own clock (see
			// `ExpiryClock`): a fixed 50 ms expiry and a 100 ms sleep on the host
			// read a Redis key after the server had already expired it on a
			// loaded run — or before, when the server's clock lagged the host's.
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
