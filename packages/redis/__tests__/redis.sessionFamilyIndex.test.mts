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
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { SessionFamilyIndexClient } from "#/clients.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { createRedisSessionFamilyIndex } from "#/sessionFamilyIndex.mjs";
import {
	runSessionEndContract,
	runSessionFamilyIndexContract,
} from "./sessionFamilyIndex.contract.mjs";
import {
	aheadOfServer,
	serverDeadlines,
	serverPasses,
	type TestRedis,
	testRedis,
} from "./support/redis.mjs";

let at: TestRedis;
let raw: Redis;

beforeAll(async () => {
	at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	raw?.disconnect();
});

let suiteCounter = 0;
const freshIndex = async (): Promise<SessionFamilyIndex> => {
	suiteCounter += 1;
	const { sessionFamilyIndexClient } = makeIoredisClients(raw);
	return createRedisSessionFamilyIndex({
		client: sessionFamilyIndexClient,
		keyPrefix: `t16:${suiteCounter}:fi:`,
		endedKeyPrefix: `t16:${suiteCounter}:fi-ended:`,
	});
};

runSessionFamilyIndexContract(freshIndex, { expiry: serverDeadlines(() => raw) });
runSessionEndContract(freshIndex, { expiry: serverDeadlines(() => raw) });

/** An index that claims the session-end capability, over `client`. */
const capable = (
	client: SessionFamilyIndexClient,
	prefix: string,
): SessionFamilyIndex & SupportsSessionEnd => {
	const idx = createRedisSessionFamilyIndex({
		client,
		keyPrefix: `${prefix}fi:`,
		endedKeyPrefix: `${prefix}fi-ended:`,
	});
	if (!supportsSessionEnd(idx))
		throw new Error("the Redis index does not claim SupportsSessionEnd");
	return idx;
};

// ---------------------------------------------------------------------------
// Concurrency cases
// ---------------------------------------------------------------------------

describe("SessionFamilyIndex concurrency", () => {
	it("100 parallel distinct familyIds → all 100 land", async () => {
		const { sessionFamilyIndexClient } = makeIoredisClients(raw);
		const idx = createRedisSessionFamilyIndex({
			client: sessionFamilyIndexClient,
			keyPrefix: "t16:conc1:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		await Promise.all(
			Array.from({ length: 100 }, (_, i) => idx.addFamilyId("sid-conc", `fam-${i}`, expiresAt)),
		);
		const list = await idx.listFamilyIds("sid-conc");
		expect(list).toHaveLength(100);
		const ids = new Set(list);
		expect(ids.size).toBe(100);
		for (let i = 0; i < 100; i++) {
			expect(ids.has(`fam-${i}`)).toBe(true);
		}
	});

	it("100 parallel same familyId → 1 entry (ZADD NX dedup)", async () => {
		const { sessionFamilyIndexClient } = makeIoredisClients(raw);
		const idx = createRedisSessionFamilyIndex({
			client: sessionFamilyIndexClient,
			keyPrefix: "t16:conc2:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		await Promise.all(
			Array.from({ length: 100 }, () => idx.addFamilyId("sid-dedup", "fam-dedup", expiresAt)),
		);
		const list = await idx.listFamilyIds("sid-dedup");
		expect(list).toHaveLength(1);
		expect(list[0]).toBe("fam-dedup");
	});

	it("an add that falls between an end's mark and its listing is listed by the end and answers ended", async () => {
		// The end's listing is held once its mark is written, and the add runs
		// to its answer in that gap, on a connection of its own.
		const { sessionFamilyIndexClient: base } = makeIoredisClients(raw);
		let markWritten!: () => void;
		const marked = new Promise<void>((resolve) => {
			markWritten = resolve;
		});
		let releaseListing!: () => void;
		const listingHeld = new Promise<void>((resolve) => {
			releaseListing = resolve;
		});
		const gated: SessionFamilyIndexClient = {
			...base,
			zRange: async (key, start, stop) => {
				markWritten();
				await listingHeld;
				return base.zRange(key, start, stop);
			},
		};
		const grantConnection = new Redis(at);
		try {
			const ending = capable(gated, "t16:between:");
			const granting = capable(
				makeIoredisClients(grantConnection).sessionFamilyIndexClient,
				"t16:between:",
			);
			const expiresAt = new Date(Date.now() + 60_000);
			const listing = ending.endSession("sid-between", expiresAt);
			await marked;
			const answer = await granting.addFamilyIdUnlessEnded("sid-between", "fam-A", expiresAt);
			releaseListing();
			expect(answer).toBe("ended");
			expect(await listing).toContain("fam-A");
		} finally {
			grantConnection.disconnect();
		}
	});

	it("500 add/end pairs over two connections, the second side started after a varying lag: in every pair the end lists the family or the add answers ended", async () => {
		// One connection stands for the replica that serves the logout, the
		// other for the one that serves the grant. Each pair has a sid of its
		// own; which side starts first alternates, and the other starts after
		// 0 to 11 event-loop turns.
		const logoutConnection = new Redis(at);
		const grantConnection = new Redis(at);
		const turns = (n: number): Promise<void> =>
			n === 0
				? Promise.resolve()
				: new Promise((resolve) => setImmediate(() => resolve(turns(n - 1))));
		try {
			const logout = capable(
				makeIoredisClients(logoutConnection).sessionFamilyIndexClient,
				"t16:pairs:",
			);
			const grant = capable(
				makeIoredisClients(grantConnection).sessionFamilyIndexClient,
				"t16:pairs:",
			);
			const expiresAt = new Date(Date.now() + 60_000);
			const pair = async (i: number) => {
				const sid = `sid-pair-${i}`;
				const familyId = `fam-${i}`;
				const lag = turns(Math.floor(i / 2) % 12);
				if (i % 2 === 0) {
					const ending = logout.endSession(sid, expiresAt);
					const adding = lag.then(() => grant.addFamilyIdUnlessEnded(sid, familyId, expiresAt));
					const [listed, answer] = await Promise.all([ending, adding]);
					return { familyId, listed, answer };
				}
				const adding = grant.addFamilyIdUnlessEnded(sid, familyId, expiresAt);
				const ending = lag.then(() => logout.endSession(sid, expiresAt));
				const [answer, listed] = await Promise.all([adding, ending]);
				return { familyId, listed, answer };
			};
			const pairs = [];
			for (let wave = 0; wave < 20; wave += 1) {
				pairs.push(
					...(await Promise.all(Array.from({ length: 25 }, (_, j) => pair(wave * 25 + j)))),
				);
			}
			const neither = pairs.filter((p) => !p.listed.includes(p.familyId) && p.answer !== "ended");
			expect(neither).toEqual([]);
		} finally {
			logoutConnection.disconnect();
			grantConnection.disconnect();
		}
	});
});

// ---------------------------------------------------------------------------
// The mark's key
// ---------------------------------------------------------------------------

describe("SessionFamilyIndex — the ended mark's key", () => {
	it("is a key of its own under endedKeyPrefix, expiring at expiresAt plus the clock-skew allowance, beside the family set", async () => {
		const idx = capable(makeIoredisClients(raw).sessionFamilyIndexClient, "t16:layout:");
		const expiresAt = new Date(Date.now() + 60_000);
		await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt);
		await idx.endSession("sid-1", expiresAt);
		expect(await raw.type("t16:layout:fi-ended:sid-1")).toBe("string");
		expect(await raw.pexpiretime("t16:layout:fi-ended:sid-1")).toBe(
			expiresAt.getTime() + DEFAULT_CLOCK_SKEW_MS,
		);
		expect(await raw.zrange("t16:layout:fi:sid-1", "0", "-1")).toEqual(["fam-A"]);
	});

	it("outlives removeBySid, which removes the family set alone", async () => {
		const idx = capable(makeIoredisClients(raw).sessionFamilyIndexClient, "t16:layout2:");
		const expiresAt = new Date(Date.now() + 60_000);
		await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt);
		await idx.endSession("sid-1", expiresAt);
		await idx.removeBySid("sid-1");
		expect(await raw.exists("t16:layout2:fi:sid-1")).toBe(0);
		expect(await raw.exists("t16:layout2:fi-ended:sid-1")).toBe(1);
	});

	it("stands past expiresAt, written by an end that came after it, and lapses once the allowance has passed on the server", async () => {
		const idx = capable(makeIoredisClients(raw).sessionFamilyIndexClient, "t16:lapse:");
		const markLapses = await aheadOfServer(() => raw)();
		const expiresAt = new Date(markLapses.getTime() - DEFAULT_CLOCK_SKEW_MS);
		await idx.endSession("sid-1", expiresAt);
		expect(await raw.exists("t16:lapse:fi-ended:sid-1")).toBe(1);
		expect(await raw.pexpiretime("t16:lapse:fi-ended:sid-1")).toBe(markLapses.getTime());
		await serverPasses(() => raw)(markLapses.getTime());
		expect(await raw.exists("t16:lapse:fi-ended:sid-1")).toBe(0);
	});
});

describe("SessionFamilyIndex — two hosts whose clocks disagree about expiresAt", () => {
	it("an end on a host whose clock is past expiresAt still marks the session: an add on a host whose clock is before it answers ended", async () => {
		// One index per host over its own connection; each host's clock is
		// injected in turn. The server's clock is real, and the session's
		// expiresAt a minute ahead of it.
		const logoutHost = capable(makeIoredisClients(raw).sessionFamilyIndexClient, "t16:hosts:");
		const grantConnection = new Redis(at);
		const grantHost = capable(
			makeIoredisClients(grantConnection).sessionFamilyIndexClient,
			"t16:hosts:",
		);
		const expiresAt = new Date(Date.now() + 60_000);
		try {
			vi.useFakeTimers({ toFake: ["Date"] });
			vi.setSystemTime(expiresAt.getTime() + 1_000);
			expect(await logoutHost.endSession("sid-1", expiresAt)).toEqual([]);
			vi.setSystemTime(expiresAt.getTime() - 1_000);
			expect(await grantHost.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt)).toBe("ended");
		} finally {
			vi.useRealTimers();
			grantConnection.disconnect();
		}
	});
});
