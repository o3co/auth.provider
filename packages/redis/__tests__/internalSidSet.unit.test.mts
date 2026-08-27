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

// Construction-time validation for the sid-keyed SET helper. Round-trip
// behaviour against a real Redis lives in `internalSidSet.test.mts`.
//
// Copilot review on PR #352: swept from the `pageSize` hole in
// `createRedisSidSortedSet`. `scanCount` is an `SSCAN COUNT` hint rather than a
// loop step, so it cannot hang — but Redis refuses a non-positive COUNT, and
// discovering that on the logout path is no better. Same guard, same message.

import { describe, expect, it, vi } from "vitest";
import type { RedisSidSetClient } from "../src/internal/redisSidSet.mjs";
import { createRedisSidSet } from "../src/internal/redisSidSet.mjs";

const client: RedisSidSetClient = {
	sAddWithTtl: vi.fn(async () => {}),
	sRem: vi.fn(async () => 0),
	sScanIterator: vi.fn(() => (async function* () {})()),
	unlink: vi.fn(async () => 0),
};

describe("createRedisSidSet validates scanCount at construction", () => {
	it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])("rejects %p", (scanCount) => {
		expect(() => createRedisSidSet({ client, keyPrefix: "t:", scanCount })).toThrow(
			/scanCount must be a positive integer/,
		);
	});

	it("accepts an omitted scanCount (defaults to 100)", () => {
		expect(() => createRedisSidSet({ client, keyPrefix: "t:" })).not.toThrow();
	});

	it("accepts a positive integer", () => {
		expect(() => createRedisSidSet({ client, keyPrefix: "t:", scanCount: 1 })).not.toThrow();
	});
});
