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

import { describe, expect, it } from "vitest";
import { createRedisSingleUseTokenStore } from "#/single-use-tokens/adapters/redis.mjs";
import { SingleUseTokenError } from "#/single-use-tokens/types.mjs";
import { createFakeRedis } from "./fakeRedis.mjs";

describe("RedisSingleUseTokenStore — issue", () => {
	it("kind is 'redis'", () => {
		const s = createRedisSingleUseTokenStore({ client: createFakeRedis() });
		expect(s.kind).toBe("redis");
	});

	it("issue stores an issued marker that survives until expiresAt", async () => {
		const client = createFakeRedis();
		const s = createRedisSingleUseTokenStore({ client });
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		// The issued marker is the value `"issued"` under the prefixed canonical key.
		const slots = [...client._store.values()];
		expect(slots).toHaveLength(1);
		expect(slots[0]?.value).toBe("issued");
	});

	it("issue rejects expiresAt <= now with 'expired-at-issue' (no SET to redis)", async () => {
		const client = createFakeRedis();
		const s = createRedisSingleUseTokenStore({ client });
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() - 1)),
		).rejects.toMatchObject({ reason: "expired-at-issue" });
		expect(client._store.size).toBe(0);
	});

	it("issue throws 'duplicate' when (scope, key) already exists (issued marker)", async () => {
		const s = createRedisSingleUseTokenStore({ client: createFakeRedis() });
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000)),
		).rejects.toMatchObject({ name: "SingleUseTokenError", reason: "duplicate" });
	});

	it("uses keyPrefix when supplied", async () => {
		const client = createFakeRedis();
		const s = createRedisSingleUseTokenStore({ client, keyPrefix: "myapp:stk:" });
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		const keys = [...client._store.keys()];
		expect(keys[0]?.startsWith("myapp:stk:")).toBe(true);
	});
});

describe("RedisSingleUseTokenStore — markSeen", () => {
	it("returns 'fresh' on first call", async () => {
		const s = createRedisSingleUseTokenStore({ client: createFakeRedis() });
		const r = await s.markSeen("jwt-bearer:iss", "j1", new Date(Date.now() + 60_000));
		expect(r).toEqual({ outcome: "fresh" });
	});

	it("returns 'replayed' on second call within TTL", async () => {
		const s = createRedisSingleUseTokenStore({ client: createFakeRedis() });
		await s.markSeen("jwt-bearer:iss", "j1", new Date(Date.now() + 60_000));
		const r = await s.markSeen("jwt-bearer:iss", "j1", new Date(Date.now() + 60_000));
		expect(r).toEqual({ outcome: "replayed" });
	});

	it("rejects expiresAt <= now with 'expired-at-issue'", async () => {
		const s = createRedisSingleUseTokenStore({ client: createFakeRedis() });
		await expect(
			s.markSeen("jwt-bearer:iss", "j1", new Date(Date.now() - 1)),
		).rejects.toBeInstanceOf(SingleUseTokenError);
	});
});
