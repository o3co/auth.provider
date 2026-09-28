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

// How the Redis federation grant store compares an intent handle where the
// comparison is not in a script (#631): `isCurrentIntent` reads the record and
// compares in this process. The handle is a capability the browser carries,
// and the port has every adapter compare it in constant time — the memory
// adapter and the scripts' `fg_same` do. A timing property is not one the
// contract suite can observe, so this pins the helper the comparison goes
// through, which is the invariant: core's `constantTimeStringEqual`, and no
// `===`.

import { constantTimeStringEqual } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createRedisFederationGrantStore } from "../src/federation-grant-store.mjs";
import { makeIoredisFederationGrantStoreClient } from "../src/ioredis.mjs";
import { testRedis } from "./support/redis.mjs";

vi.mock("@o3co/auth-provider-core", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@o3co/auth-provider-core")>();
	return { ...actual, constantTimeStringEqual: vi.fn(actual.constantTimeStringEqual) };
});

const compare = vi.mocked(constantTimeStringEqual);

let redis: Redis;
let run = 0;
let prefix = "";
let T0 = new Date();

beforeAll(async () => {
	redis = new Redis(await testRedis());
});

afterAll(async () => {
	await redis?.quit();
});

beforeEach(() => {
	run += 1;
	prefix = `fgh${run}:`;
	T0 = new Date(Math.floor(Date.now() / 1000) * 1000 + 137);
	compare.mockClear();
});

describe("isCurrentIntent compares the handle in constant time (#631)", () => {
	it("goes through core's constantTimeStringEqual, with the stored handle and the one asked about", async () => {
		const store = createRedisFederationGrantStore({
			client: makeIoredisFederationGrantStoreClient(redis),
			keyPrefix: prefix,
			encryption: { mode: "required", keys: [{ id: "k-1", key: Buffer.alloc(32, 1) }] },
		});
		await store.createPending({
			id: "g-1",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h-1", expiresAt: new Date(T0.getTime() + 600_000) },
			now: T0,
		});

		expect(await store.isCurrentIntent("g-1", "h-2", T0)).toBe(false);
		expect(compare).toHaveBeenCalledWith("h-1", "h-2");
		expect(await store.isCurrentIntent("g-1", "h-1", T0)).toBe(true);
		expect(compare).toHaveBeenLastCalledWith("h-1", "h-1");
	});
});
