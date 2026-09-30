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

import { supportsSessionEnd } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import type { SessionFamilyIndexClient, SessionSidSortedSetMultiClient } from "../src/clients.mjs";
import {
	createRedisSessionFamilyIndex,
	redisSessionFamilyIndexBuilder,
} from "../src/sessionFamilyIndex.mjs";

/** A client that logs when each call starts and when its reply is in. */
const recordingClient = (options: { readonly marked?: boolean } = {}) => {
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
		writeEndMark: (key, msTimestamp) => reply(`writeEndMark ${key} ${msTimestamp}`, undefined),
		hasEndMark: (key) => reply(`hasEndMark ${key}`, options.marked ?? false),
	};
	return { client, log };
};

const FUTURE = () => new Date(Date.now() + 60_000);

describe("createRedisSessionFamilyIndex — the session-end capability", () => {
	it("is claimed over a client with writeEndMark and hasEndMark, given endedKeyPrefix", () => {
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

	it("is not claimed over a client without the mark's methods, or with one of them", () => {
		const { client } = recordingClient();
		const { writeEndMark: _write, hasEndMark: _has, ...sortedSetOnly } = client;
		const { hasEndMark: _hasOnly, ...writeOnly } = client;
		const { writeEndMark: _writeOnly, ...readOnly } = client;
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

	it("endSession writes the mark at expiresAt, and lists only once the write is in", async () => {
		const { idx, log } = capable();
		const expiresAt = FUTURE();
		await idx.endSession("sid-1", expiresAt);
		expect(log).toEqual([
			`writeEndMark t:fi-ended:sid-1 ${expiresAt.getTime()} sent`,
			`writeEndMark t:fi-ended:sid-1 ${expiresAt.getTime()} replied`,
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
			"hasEndMark t:fi-ended:sid-1 sent",
			"hasEndMark t:fi-ended:sid-1 replied",
		]);
	});

	it("addFamilyIdUnlessEnded answers added when the mark is not there", async () => {
		const { idx } = capable(false);
		expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", FUTURE())).toBe("added");
	});

	it("an end past expiresAt writes no mark, and still lists", async () => {
		const { idx, log } = capable();
		await idx.endSession("sid-1", new Date(Date.now() - 1));
		expect(log).toEqual(["zRange t:fi:sid-1 sent", "zRange t:fi:sid-1 replied"]);
	});

	it("an add past expiresAt answers ended and sends nothing", async () => {
		const { idx, log } = capable();
		expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", new Date(Date.now() - 1))).toBe(
			"ended",
		);
		expect(log).toEqual([]);
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
	it("keeps the mark under the bundle's prefix, ss:fi-ended:, by default", async () => {
		const { client, log } = recordingClient();
		const idx = redisSessionFamilyIndexBuilder({ client } as never, {
			lifecycle: undefined,
		} as never);
		if (!supportsSessionEnd(idx)) throw new Error("the index does not claim SupportsSessionEnd");
		const expiresAt = FUTURE();
		await idx.endSession("sid-1", expiresAt);
		expect(log[0]).toBe(`writeEndMark ss:fi-ended:sid-1 ${expiresAt.getTime()} sent`);
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
		expect(log[0]).toBe(`writeEndMark x:fi-ended:sid-1 ${expiresAt.getTime()} sent`);
	});
});
