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

// #291 — the sid-keyed ZSET is read in rank pages, not `ZRANGE key 0 -1`.
//
// `list` used to ask for the whole sorted set in one command; the reply size
// grew with how many refresh-token families or federations a session had
// accumulated, and logout reads both. These tests pin the paging and the
// ordering it must not disturb. Round-trip behaviour against a real Redis is
// covered in `internalSidSortedSet.test.mts`.

import { describe, expect, it, vi } from "vitest";
import type { SessionSidSortedSetClient, SessionSidSortedSetMultiClient } from "../src/clients.mjs";
import { createRedisSidSortedSet } from "../src/internal/redisSidSortedSet.mjs";

function createClient(members: string[]) {
	const multi: SessionSidSortedSetMultiClient = {
		pExpireAt: vi.fn(() => multi),
		pExpireGT: vi.fn(() => multi),
		zAdd: vi.fn(() => multi),
		exec: vi.fn(async () => []),
	};
	return {
		unlink: vi.fn(async () => 1),
		multi: vi.fn(() => multi),
		pExpireAt: vi.fn(async () => 1),
		pExpireGT: vi.fn(async () => 1),
		zAdd: vi.fn(async () => 1),
		zRange: vi.fn(async (_key: string, start: number, stop: number) =>
			members.slice(start, stop + 1),
		),
		zRem: vi.fn(async () => 1),
	} satisfies SessionSidSortedSetClient;
}

describe("#291 — createRedisSidSortedSet.list pages by rank", () => {
	it("never asks for the whole set in one command", async () => {
		const client = createClient(["a", "b", "c"]);
		const zset = createRedisSidSortedSet({ client, keyPrefix: "t:" });
		await zset.list("sid-1");
		for (const [, , stop] of client.zRange.mock.calls) {
			expect(stop).not.toBe(-1);
		}
		expect(client.zRange).toHaveBeenCalledWith("t:sid-1", 0, 99);
	});

	it("walks successive rank pages until a short page ends the read", async () => {
		const members = Array.from({ length: 250 }, (_, i) => `m-${i}`);
		const client = createClient(members);
		const zset = createRedisSidSortedSet({ client, keyPrefix: "t:" });
		expect(await zset.list("sid-1")).toEqual(members);
		expect(client.zRange.mock.calls.map(([, start, stop]) => [start, stop])).toEqual([
			[0, 99],
			[100, 199],
			[200, 299],
		]);
	});

	it("stops after a full final page returns nothing (exact multiple of the page size)", async () => {
		const members = Array.from({ length: 100 }, (_, i) => `m-${i}`);
		const client = createClient(members);
		const zset = createRedisSidSortedSet({ client, keyPrefix: "t:" });
		expect(await zset.list("sid-1")).toEqual(members);
		expect(client.zRange).toHaveBeenCalledTimes(2);
	});

	it("preserves insertion order across page boundaries (load-bearing for A4 §5.4)", async () => {
		// `SessionFederationIndex.listFederations` order decides which IdP
		// `routes/logout.mts` redirects to. Paging must not reorder it.
		const members = Array.from({ length: 150 }, (_, i) => `idp-${i}`);
		const client = createClient(members);
		const zset = createRedisSidSortedSet({ client, keyPrefix: "t:" });
		const listed = await zset.list("sid-1");
		expect(listed[0]).toBe("idp-0");
		expect(listed[99]).toBe("idp-99");
		expect(listed[100]).toBe("idp-100");
		expect(listed.at(-1)).toBe("idp-149");
	});

	it("returns an empty array for a sid with no key", async () => {
		const client = createClient([]);
		const zset = createRedisSidSortedSet({ client, keyPrefix: "t:" });
		expect(await zset.list("ghost")).toEqual([]);
		expect(client.zRange).toHaveBeenCalledTimes(1);
	});
});

describe("#291 — createRedisSidSortedSet.removeBySid uses UNLINK", () => {
	it("unlinks the sid's key", async () => {
		const client = createClient([]);
		const zset = createRedisSidSortedSet({ client, keyPrefix: "t:" });
		await zset.removeBySid("sid-1");
		expect(client.unlink).toHaveBeenCalledWith("t:sid-1");
	});
});
