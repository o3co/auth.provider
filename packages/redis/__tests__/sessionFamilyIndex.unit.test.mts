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

// The Redis family index against a recording client, without Redis: when it
// claims the session-end capability, which keys it writes, and the order of
// its two operations — each one's reply in before the next is sent. The
// contract suite and the concurrency cases against Redis are in
// `redis.sessionFamilyIndex.test.mts`.

import { DEFAULT_CLOCK_SKEW_MS, supportsSessionEnd } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionFamilyIndexClient, SessionSidSortedSetMultiClient } from "../src/clients.mjs";
import {
	createRedisSessionFamilyIndex,
	redisSessionFamilyIndexBuilder,
} from "../src/sessionFamilyIndex.mjs";

/** A client that logs when each call starts and when its reply is in. */
const recordingClient = (
	options: { readonly marked?: boolean; readonly beforeMarkRead?: () => void } = {},
) => {
	const log: string[] = [];
	const reply = async <T,>(name: string, value: T): Promise<T> => {
		log.push(`${name} sent`);
		await new Promise((resolve) => setTimeout(resolve, 1));
		log.push(`${name} replied`);
		return value;
	};
	const multi: SessionSidSortedSetMultiClient = {
		pExpireAt: () => multi,
		pExpireGT: () => multi,
		zAdd: () => multi,
		exec: () => reply("exec", []),
	};
	const client: SessionFamilyIndexClient = {
		unlink: (key) => reply(`unlink ${key}`, 1),
		multi: () => multi,
		pExpireAt: () => reply("pExpireAt", 1),
		pExpireGT: () => reply("pExpireGT", 1),
		zAdd: () => reply("zAdd", 1),
		zRange: (key) => reply(`zRange ${key}`, []),
		zRem: () => reply("zRem", 1),
		writeEndedMark: (key, msTimestamp) => reply(`writeEndedMark ${key} ${msTimestamp}`, undefined),
		hasEndedMark: (key) => {
			options.beforeMarkRead?.();
			return reply(`hasEndedMark ${key}`, options.marked ?? false);
		},
	};
	return { client, log };
};

const FUTURE = () => new Date(Date.now() + 60_000);

describe("createRedisSessionFamilyIndex — the session-end capability", () => {
	it("is claimed over a client with writeEndedMark and hasEndedMark, given endedKeyPrefix", () => {
		const { client } = recordingClient();
		const idx = createRedisSessionFamilyIndex({
			client,
			keyPrefix: "t:fi:",
			endedKeyPrefix: "t:fi-ended:",
		});
		expect(supportsSessionEnd(idx)).toBe(true);
	});

	it("is not claimed without endedKeyPrefix, and the index still works as before", async () => {
		const { client, log } = recordingClient();
		const idx = createRedisSessionFamilyIndex({ client, keyPrefix: "t:fi:" });
		expect(supportsSessionEnd(idx)).toBe(false);
		await idx.listFamilyIds("sid-1");
		expect(log).toEqual(["zRange t:fi:sid-1 sent", "zRange t:fi:sid-1 replied"]);
	});

	it("refuses an endedKeyPrefix that overlaps keyPrefix: neither may start with the other", () => {
		// A mark's `SET` at a family set's key would replace the set.
		const { client } = recordingClient();
		for (const [keyPrefix, endedKeyPrefix] of [
			["t:fi:", "t:fi:"],
			["t:fi:", "t:fi:ended:"],
			["t:ended:fi:", "t:ended:"],
		] as const) {
			expect(() => createRedisSessionFamilyIndex({ client, keyPrefix, endedKeyPrefix })).toThrow(
				RangeError,
			);
		}
	});

	it("is not claimed over a client without the mark's methods, or with one of them", () => {
		const { client } = recordingClient();
		const { writeEndedMark: _write, hasEndedMark: _has, ...sortedSetOnly } = client;
		const { hasEndedMark: _hasOnly, ...writeOnly } = client;
		const { writeEndedMark: _writeOnly, ...readOnly } = client;
		for (const partial of [sortedSetOnly, writeOnly, readOnly]) {
			const idx = createRedisSessionFamilyIndex({
				client: partial,
				keyPrefix: "t:fi:",
				endedKeyPrefix: "t:fi-ended:",
			});
			expect(supportsSessionEnd(idx)).toBe(false);
		}
	});
});

describe("createRedisSessionFamilyIndex — the order of the two operations", () => {
	const capable = (marked = false) => {
		const { client, log } = recordingClient({ marked });
		const idx = createRedisSessionFamilyIndex({
			client,
			keyPrefix: "t:fi:",
			endedKeyPrefix: "t:fi-ended:",
		});
		if (!supportsSessionEnd(idx)) throw new Error("the index does not claim SupportsSessionEnd");
		return { idx, log };
	};

	it("endSession writes the mark to last expiresAt plus the clock-skew allowance, and lists only once the write is in", async () => {
		const { idx, log } = capable();
		const expiresAt = FUTURE();
		const until = expiresAt.getTime() + DEFAULT_CLOCK_SKEW_MS;
		await idx.endSession("sid-1", expiresAt);
		expect(log).toEqual([
			`writeEndedMark t:fi-ended:sid-1 ${until} sent`,
			`writeEndedMark t:fi-ended:sid-1 ${until} replied`,
			"zRange t:fi:sid-1 sent",
			"zRange t:fi:sid-1 replied",
		]);
	});

	it("addFamilyIdUnlessEnded adds the family, and reads the mark only once the add is in", async () => {
		const { idx, log } = capable(true);
		expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", FUTURE())).toBe("ended");
		expect(log).toEqual([
			"exec sent",
			"exec replied",
			"hasEndedMark t:fi-ended:sid-1 sent",
			"hasEndedMark t:fi-ended:sid-1 replied",
		]);
	});

	it("addFamilyIdUnlessEnded answers added when the mark is not there", async () => {
		const { idx } = capable(false);
		expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", FUTURE())).toBe("added");
	});

	it("an end past expiresAt still writes the mark, to last the clock-skew allowance after it", async () => {
		const { idx, log } = capable();
		const expiresAt = new Date(Date.now() - 1_000);
		await idx.endSession("sid-1", expiresAt);
		expect(log[0]).toBe(
			`writeEndedMark t:fi-ended:sid-1 ${expiresAt.getTime() + DEFAULT_CLOCK_SKEW_MS} sent`,
		);
		expect(log[2]).toBe("zRange t:fi:sid-1 sent");
	});

	it("an end past expiresAt and the allowance after it writes no mark, and still lists", async () => {
		const { idx, log } = capable();
		await idx.endSession("sid-1", new Date(Date.now() - DEFAULT_CLOCK_SKEW_MS - 1_000));
		expect(log).toEqual(["zRange t:fi:sid-1 sent", "zRange t:fi:sid-1 replied"]);
	});

	it("an add past expiresAt answers ended and sends nothing", async () => {
		const { idx, log } = capable();
		expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", new Date(Date.now() - 1))).toBe(
			"ended",
		);
		expect(log).toEqual([]);
	});

	describe("on a clock that passes expiresAt while the add waits on Redis", () => {
		afterEach(() => {
			vi.useRealTimers();
		});

		it("answers ended when the mark is gone by the time it is read", async () => {
			// The add starts inside the session's life, and the clock passes
			// expiresAt before the mark is read: an absent mark then says nothing.
			vi.useFakeTimers({ toFake: ["Date"] });
			const expiresAt = new Date(Date.now() + 60_000);
			vi.setSystemTime(expiresAt.getTime() - 1);
			const { client } = recordingClient({
				marked: false,
				beforeMarkRead: () => vi.setSystemTime(expiresAt.getTime() + 1),
			});
			const idx = createRedisSessionFamilyIndex({
				client,
				keyPrefix: "t:fi:",
				endedKeyPrefix: "t:fi-ended:",
			});
			if (!supportsSessionEnd(idx)) throw new Error("the index does not claim SupportsSessionEnd");
			expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt)).toBe("ended");
		});
	});

	it("an Invalid Date is refused by both before anything is sent", async () => {
		const { idx, log } = capable();
		await expect(idx.endSession("sid-1", new Date(Number.NaN))).rejects.toThrow(RangeError);
		await expect(
			idx.addFamilyIdUnlessEnded("sid-1", "fam-A", new Date(Number.NaN)),
		).rejects.toThrow(RangeError);
		expect(log).toEqual([]);
	});
});

describe("redisSessionFamilyIndexBuilder — the ended mark", () => {
	it("boots with the keyPrefix it always took, empty or short, over a plain sorted-set client", () => {
		const { client } = recordingClient();
		const { writeEndedMark: _write, hasEndedMark: _has, ...sortedSetOnly } = client;
		for (const keyPrefix of ["", "ss:", "s", "ss:fi"]) {
			const idx = redisSessionFamilyIndexBuilder(
				{ client: sortedSetOnly, keyPrefix } as never,
				{ lifecycle: undefined } as never,
			);
			expect(idx.kind).toBe("redis");
			expect(supportsSessionEnd(idx)).toBe(false);
		}
	});

	it("given a keyPrefix of its own and no endedKeyPrefix, has no capability rather than share the bundle's marks", async () => {
		const { client, log } = recordingClient();
		for (const keyPrefix of ["", "ss:", "app:fi:"]) {
			const idx = redisSessionFamilyIndexBuilder(
				{ client, keyPrefix } as never,
				{ lifecycle: undefined } as never,
			);
			expect(supportsSessionEnd(idx)).toBe(false);
			await idx.addFamilyId("sid-1", "fam-A", FUTURE());
		}
		expect(log.filter((line) => line.includes("EndedMark"))).toEqual([]);
	});

	it("keeps the mark under the bundle's prefix, ss:fi-ended:, by default", async () => {
		const { client, log } = recordingClient();
		const idx = redisSessionFamilyIndexBuilder(
			{ client } as never,
			{ lifecycle: undefined } as never,
		);
		if (!supportsSessionEnd(idx)) throw new Error("the index does not claim SupportsSessionEnd");
		const expiresAt = FUTURE();
		await idx.endSession("sid-1", expiresAt);
		expect(log[0]).toBe(
			`writeEndedMark ss:fi-ended:sid-1 ${expiresAt.getTime() + DEFAULT_CLOCK_SKEW_MS} sent`,
		);
		expect(log[2]).toBe("zRange ss:fi:sid-1 sent");
	});

	it("takes endedKeyPrefix from its configuration", async () => {
		const { client, log } = recordingClient();
		const idx = redisSessionFamilyIndexBuilder(
			{ client, keyPrefix: "x:fi:", endedKeyPrefix: "x:fi-ended:" } as never,
			{ lifecycle: undefined } as never,
		);
		if (!supportsSessionEnd(idx)) throw new Error("the index does not claim SupportsSessionEnd");
		const expiresAt = FUTURE();
		await idx.endSession("sid-1", expiresAt);
		expect(log[0]).toBe(
			`writeEndedMark x:fi-ended:sid-1 ${expiresAt.getTime() + DEFAULT_CLOCK_SKEW_MS} sent`,
		);
	});
});
