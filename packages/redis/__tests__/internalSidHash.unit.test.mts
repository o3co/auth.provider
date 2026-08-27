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

// #291 — the sid-keyed HASH is read with a cursor, not in one reply.
//
// `listValues` used to be `HVALS`: one command returning every RP registered
// against the session, whose reply size is bounded by nothing. A session
// linked to a large number of relying parties made that a single blocking
// command on the connection every other adapter shares. These tests pin the
// cursor-based read and the duplicate handling it requires; the round-trip
// behaviour against a real Redis is covered in `internalSidHash.test.mts`.

import { describe, expect, it, vi } from "vitest";
import type { SessionRPRegistryClient, SessionRPRegistryMultiClient } from "../src/clients.mjs";
import { createRedisSidHash } from "../src/internal/redisSidHash.mjs";

type Pair = readonly [field: string, value: string];

function createClient(pages: Pair[][]) {
	const multi: SessionRPRegistryMultiClient = {
		hSet: vi.fn(() => multi),
		pExpireAt: vi.fn(() => multi),
		pExpireGT: vi.fn(() => multi),
		exec: vi.fn(async () => []),
	};
	return {
		unlink: vi.fn(async () => 1),
		hSet: vi.fn(async () => 1),
		hScanIterator: vi.fn((_key: string, _opts?: { COUNT?: number }) =>
			(async function* () {
				for (const page of pages) {
					for (const pair of page) yield pair;
				}
			})(),
		),
		multi: vi.fn(() => multi),
		pExpireAt: vi.fn(async () => 1),
		pExpireGT: vi.fn(async () => 1),
	} satisfies SessionRPRegistryClient;
}

describe("#291 — createRedisSidHash.listValues is cursor-based", () => {
	it("reads through hScanIterator rather than one unbounded reply", async () => {
		const client = createClient([[["c1", '{"a":1}']]]);
		const hash = createRedisSidHash({ client, keyPrefix: "t:" });
		expect(await hash.listValues("sid-1")).toEqual(['{"a":1}']);
		expect(client.hScanIterator).toHaveBeenCalledWith("t:sid-1", { COUNT: 100 });
	});

	it("concatenates values across cursor pages, in page order", async () => {
		const client = createClient([
			[
				["c1", "v1"],
				["c2", "v2"],
			],
			[["c3", "v3"]],
		]);
		const hash = createRedisSidHash({ client, keyPrefix: "t:" });
		expect(await hash.listValues("sid-1")).toEqual(["v1", "v2", "v3"]);
	});

	it("de-duplicates fields repeated across pages (HSCAN may return one twice)", async () => {
		// A hash that rehashes mid-iteration can hand the same field back on a
		// later cursor. Without dedup, `listRPs` would report the same relying
		// party twice and back-channel logout would notify it twice.
		const client = createClient([
			[
				["c1", "v1"],
				["c2", "v2"],
			],
			[
				["c1", "v1-newer"],
				["c3", "v3"],
			],
		]);
		const hash = createRedisSidHash({ client, keyPrefix: "t:" });
		const values = await hash.listValues("sid-1");
		expect(values).toHaveLength(3);
		expect(values).toContain("v2");
		expect(values).toContain("v3");
		// The later observation wins: it is the fresher read of that field.
		expect(values).toContain("v1-newer");
		expect(values).not.toContain("v1");
	});

	it("returns an empty array for a sid with no key", async () => {
		const client = createClient([]);
		const hash = createRedisSidHash({ client, keyPrefix: "t:" });
		expect(await hash.listValues("ghost")).toEqual([]);
	});
});

describe("#291 — createRedisSidHash.removeBySid uses UNLINK", () => {
	it("unlinks the sid's key", async () => {
		const client = createClient([]);
		const hash = createRedisSidHash({ client, keyPrefix: "t:" });
		await hash.removeBySid("sid-1");
		expect(client.unlink).toHaveBeenCalledWith("t:sid-1");
	});
});

// Copilot review on PR #352, swept from the `pageSize` hole in the sorted-set
// helper. `scanCount` cannot loop forever here — it is an `HSCAN COUNT` hint,
// and Redis rejects a non-positive one — but a command the server refuses on
// the logout path is no better than a hang. Same construction-time guard.
describe("#291 — createRedisSidHash validates scanCount at construction", () => {
	it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])("rejects %p", (scanCount) => {
		expect(() =>
			createRedisSidHash({ client: createClient([]), keyPrefix: "t:", scanCount }),
		).toThrow(/scanCount must be a positive integer/);
	});

	it("accepts an omitted scanCount (defaults to 100)", () => {
		expect(() => createRedisSidHash({ client: createClient([]), keyPrefix: "t:" })).not.toThrow();
	});
});
