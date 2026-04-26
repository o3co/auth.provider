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

	it("issue stores an issued marker as a hash field that survives until expiresAt", async () => {
		const client = createFakeRedis();
		const s = createRedisSingleUseTokenStore({ client });
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		const slots = [...client._store.values()];
		expect(slots).toHaveLength(1);
		const slot = slots[0];
		expect(slot?.kind).toBe("hash");
		if (slot?.kind === "hash") {
			expect(slot.fields.get("issued")).toBe("1");
		}
	});

	it("issue rejects expiresAt <= now with 'expired-at-issue' (no SET to redis)", async () => {
		const client = createFakeRedis();
		const s = createRedisSingleUseTokenStore({ client });
		await expect(s.issue("webauthn:reg", "k1", new Date(Date.now() - 1))).rejects.toMatchObject({
			reason: "expired-at-issue",
		});
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

describe("RedisSingleUseTokenStore — consume", () => {
	it("returns 'unknown' when nothing was issued", async () => {
		const s = createRedisSingleUseTokenStore({ client: createFakeRedis() });
		const r = await s.consume("webauthn:reg", "never");
		expect(r).toEqual({ outcome: "unknown" });
	});

	it("returns 'consumed' on first consume of an issued token", async () => {
		const s = createRedisSingleUseTokenStore({ client: createFakeRedis() });
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		const r = await s.consume("webauthn:reg", "k1");
		expect(r).toEqual({ outcome: "consumed" });
	});

	it("returns 'replayed' on subsequent consume calls within TTL", async () => {
		const s = createRedisSingleUseTokenStore({ client: createFakeRedis() });
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		await s.consume("webauthn:reg", "k1");
		const r = await s.consume("webauthn:reg", "k1");
		expect(r).toEqual({ outcome: "replayed" });
	});

	it("writes a 'consumed' field with a timestamp, preserving the 'issued' field and TTL", async () => {
		const client = createFakeRedis();
		const s = createRedisSingleUseTokenStore({ client });
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		const keyName = [...client._store.keys()][0] ?? "";
		const slot = client._store.get(keyName);
		const beforeExp = slot?.expiresAtMs ?? 0;
		await s.consume("webauthn:reg", "k1");
		const after = client._store.get(keyName);
		expect(after?.kind).toBe("hash");
		if (after?.kind === "hash") {
			expect(after.fields.get("issued")).toBe("1");
			expect(after.fields.get("consumed")).toMatch(/^\d+$/);
		}
		// TTL preserved (PEXPIRE was called only on issue).
		expect(after?.expiresAtMs).toBe(beforeExp);
	});

	it("issue throws 'duplicate' for a (scope, key) that is consumed but not yet expired", async () => {
		const s = createRedisSingleUseTokenStore({ client: createFakeRedis() });
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		await s.consume("webauthn:reg", "k1");
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000)),
		).rejects.toMatchObject({ reason: "duplicate" });
	});
});

describe("RedisSingleUseTokenStore — poisoning resistance", () => {
	it("attacker pre-consume followed by legit issue → consume returns 'consumed' (not false 'replayed')", async () => {
		const client = createFakeRedis();
		const s = createRedisSingleUseTokenStore({ client });

		// Attacker pre-poisons the (scope, key) by calling consume on a never-issued key.
		const attackerOutcome = await s.consume("webauthn:reg", "guessable-key");
		expect(attackerOutcome).toEqual({ outcome: "unknown" });

		// The poison residue should have been cleaned up — verify by inspecting the store.
		expect(client._store.size).toBe(0);

		// Legitimate user issues + consumes the same (scope, key).
		await s.issue("webauthn:reg", "guessable-key", new Date(Date.now() + 60_000));
		const legitOutcome = await s.consume("webauthn:reg", "guessable-key");

		// MUST return 'consumed', NOT 'replayed'. If this asserts 'replayed',
		// the poisoning vulnerability has regressed.
		expect(legitOutcome).toEqual({ outcome: "consumed" });
	});

	it("attacker spamming consume on random keys does not accumulate TTL-less hashes", async () => {
		const client = createFakeRedis();
		const s = createRedisSingleUseTokenStore({ client });

		for (let i = 0; i < 10; i++) {
			await s.consume("webauthn:reg", `attacker-${i}`);
		}
		// All 10 consume calls should have cleaned up after themselves.
		expect(client._store.size).toBe(0);
	});
});

describe("RedisSingleUseTokenStore — issue PEXPIRE failure handling", () => {
	it("cleans up and throws when pExpire returns 0", async () => {
		// Arrange: a fake client whose pExpire reports failure to set TTL.
		const inner = createFakeRedis();
		let pExpireCalls = 0;
		let delCalls = 0;
		const client = {
			...inner,
			async pExpire(_k: string, _ms: number) {
				pExpireCalls++;
				return 0; // simulate "key did not exist" response
			},
			async del(k: string) {
				delCalls++;
				return inner.del(k);
			},
		};

		const s = createRedisSingleUseTokenStore({ client });
		await expect(s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000))).rejects.toThrow(
			/failed to set TTL/,
		);

		expect(pExpireCalls).toBe(1);
		expect(delCalls).toBe(1);
		// The hash should not survive the failed issue.
		expect(inner._store.size).toBe(0);
	});
});
