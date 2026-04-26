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
import { createInMemorySingleUseTokenStore } from "#/single-use-tokens/adapters/memory.mjs";
import { SingleUseTokenError } from "#/single-use-tokens/types.mjs";

describe("InMemorySingleUseTokenStore — issue", () => {
	it("kind is 'memory'", () => {
		const s = createInMemorySingleUseTokenStore();
		expect(s.kind).toBe("memory");
	});

	it("issue stores a fresh (scope, key) without throwing", async () => {
		const s = createInMemorySingleUseTokenStore();
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000)),
		).resolves.toBeUndefined();
	});

	it("issue rejects expiresAt <= now with reason 'expired-at-issue'", async () => {
		const s = createInMemorySingleUseTokenStore();
		const past = new Date(Date.now() - 1);
		await expect(s.issue("webauthn:reg", "k1", past)).rejects.toMatchObject({
			name: "SingleUseTokenError",
			reason: "expired-at-issue",
		});
	});

	it("issue rejects exactly at expiresAt === now with 'expired-at-issue'", async () => {
		const s = createInMemorySingleUseTokenStore();
		const now = new Date(Date.now());
		await expect(s.issue("webauthn:reg", "k1", now)).rejects.toMatchObject({
			reason: "expired-at-issue",
		});
	});

	it("issue throws 'duplicate' when (scope, key) is already issued and not expired", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000)),
		).rejects.toMatchObject({ name: "SingleUseTokenError", reason: "duplicate" });
	});

	it("issue accepts re-use of (scope, key) after expiresAt has passed", async () => {
		const s = createInMemorySingleUseTokenStore();
		const justExpired = new Date(Date.now() + 5);
		await s.issue("webauthn:reg", "k1", justExpired);
		await new Promise((r) => setTimeout(r, 10));
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000)),
		).resolves.toBeUndefined();
	});

	it("issue throws SingleUseTokenError instances (not generic Error)", async () => {
		const s = createInMemorySingleUseTokenStore();
		try {
			await s.issue("a", "b", new Date(0));
			expect.fail("should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(SingleUseTokenError);
		}
	});
});

describe("InMemorySingleUseTokenStore — consume", () => {
	it("returns 'unknown' when nothing was issued", async () => {
		const s = createInMemorySingleUseTokenStore();
		const r = await s.consume("webauthn:reg", "never");
		expect(r).toEqual({ outcome: "unknown" });
	});

	it("returns 'consumed' on first consume of an issued token", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		const r = await s.consume("webauthn:reg", "k1");
		expect(r).toEqual({ outcome: "consumed" });
	});

	it("returns 'replayed' on second consume of an already-consumed token (within TTL)", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		await s.consume("webauthn:reg", "k1");
		const r = await s.consume("webauthn:reg", "k1");
		expect(r).toEqual({ outcome: "replayed" });
	});

	it("keeps returning 'replayed' until expiresAt elapses, then returns 'unknown'", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 30));
		expect((await s.consume("webauthn:reg", "k1")).outcome).toBe("consumed");
		expect((await s.consume("webauthn:reg", "k1")).outcome).toBe("replayed");
		await new Promise((r) => setTimeout(r, 50));
		expect((await s.consume("webauthn:reg", "k1")).outcome).toBe("unknown");
	});

	it("issue throws 'duplicate' for a (scope, key) that is consumed but not yet expired", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000));
		await s.consume("webauthn:reg", "k1");
		await expect(
			s.issue("webauthn:reg", "k1", new Date(Date.now() + 60_000)),
		).rejects.toMatchObject({ reason: "duplicate" });
	});

	it("concurrent consume calls for the same issued token yield exactly one 'consumed' and N-1 'replayed' (N=100)", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.issue("webauthn:reg", "race", new Date(Date.now() + 60_000));
		const calls = await Promise.all(
			Array.from({ length: 100 }, () => s.consume("webauthn:reg", "race")),
		);
		const counts = calls.reduce<Record<string, number>>((acc, r) => {
			acc[r.outcome] = (acc[r.outcome] ?? 0) + 1;
			return acc;
		}, {});
		expect(counts.consumed).toBe(1);
		expect(counts.replayed).toBe(99);
		expect(counts.unknown).toBeUndefined();
	});

	it("scope isolation: same key under different scopes do not collide", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.issue("scope:a", "k", new Date(Date.now() + 60_000));
		const r = await s.consume("scope:b", "k");
		expect(r).toEqual({ outcome: "unknown" });
	});
});

describe("InMemorySingleUseTokenStore — markSeen", () => {
	it("returns 'fresh' on first observation of (scope, key)", async () => {
		const s = createInMemorySingleUseTokenStore();
		const r = await s.markSeen("jwt-bearer:iss", "jti-1", new Date(Date.now() + 60_000));
		expect(r).toEqual({ outcome: "fresh" });
	});

	it("returns 'replayed' on second observation within TTL", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.markSeen("jwt-bearer:iss", "jti-1", new Date(Date.now() + 60_000));
		const r = await s.markSeen("jwt-bearer:iss", "jti-1", new Date(Date.now() + 60_000));
		expect(r).toEqual({ outcome: "replayed" });
	});

	it("returns 'fresh' again after the recorded expiresAt has passed", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.markSeen("jwt-bearer:iss", "jti-1", new Date(Date.now() + 30));
		await new Promise((r) => setTimeout(r, 50));
		const r = await s.markSeen("jwt-bearer:iss", "jti-1", new Date(Date.now() + 60_000));
		expect(r).toEqual({ outcome: "fresh" });
	});

	it("rejects expiresAt <= now with 'expired-at-issue'", async () => {
		const s = createInMemorySingleUseTokenStore();
		await expect(
			s.markSeen("jwt-bearer:iss", "jti-1", new Date(Date.now() - 1)),
		).rejects.toMatchObject({ reason: "expired-at-issue" });
	});

	it("scope isolation: same jti under different issuers does not collide", async () => {
		const s = createInMemorySingleUseTokenStore();
		await s.markSeen("jwt-bearer:a", "jti", new Date(Date.now() + 60_000));
		const r = await s.markSeen("jwt-bearer:b", "jti", new Date(Date.now() + 60_000));
		expect(r).toEqual({ outcome: "fresh" });
	});

	it("concurrent markSeen for the same key yields exactly one 'fresh' and N-1 'replayed'", async () => {
		const s = createInMemorySingleUseTokenStore();
		const calls = await Promise.all(
			Array.from({ length: 100 }, () =>
				s.markSeen("jwt-bearer:iss", "race", new Date(Date.now() + 60_000)),
			),
		);
		const counts = calls.reduce<Record<string, number>>((acc, r) => {
			acc[r.outcome] = (acc[r.outcome] ?? 0) + 1;
			return acc;
		}, {});
		expect(counts.fresh).toBe(1);
		expect(counts.replayed).toBe(99);
	});
});
