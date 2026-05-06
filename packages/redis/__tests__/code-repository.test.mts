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

import { beforeEach, describe, expect, it, vi } from "vitest";

const KEY_PREFIX = "oauth:code:";

// In-memory store simulating Redis
const store = new Map<string, string>();

import { RedisCodeRepository } from "../src/code-repository.mjs";

const createMockRedis = () => ({
	connect: vi.fn().mockResolvedValue(undefined),
	set: vi.fn().mockImplementation((key: string, value: string) => {
		store.set(key, value);
		return Promise.resolve("OK");
	}),
	get: vi.fn().mockImplementation((key: string) => {
		return Promise.resolve(store.get(key) ?? null);
	}),
	getDel: vi.fn().mockImplementation((key: string) => {
		const value = store.get(key) ?? null;
		store.delete(key);
		return Promise.resolve(value);
	}),
	del: vi.fn().mockImplementation((key: string) => {
		store.delete(key);
		return Promise.resolve(1);
	}),
});

describe("RedisCodeRepository", () => {
	let repo: RedisCodeRepository;

	// Minimal valid params for v0.5.1+ (D-1: client_id and redirect_uri required).
	const minimalParams = {
		client_id: "test-client",
		redirect_uri: "https://rp.example/cb",
	};

	beforeEach(async () => {
		store.clear();
		const redis = createMockRedis();
		repo = new RedisCodeRepository(redis);
		await repo.initialize();
	});

	describe("createCode", () => {
		it("generates a code string and stores it", async () => {
			const result = await repo.createCode(minimalParams);

			expect(typeof result.code).toBe("string");
			expect(result.code.length).toBeGreaterThan(0);
			// Verify it was stored with namespace prefix
			expect(store.has(`${KEY_PREFIX}${result.code}`)).toBe(true);
		});

		it("returns code with code_challenge and code_challenge_method", async () => {
			const result = await repo.createCode({
				...minimalParams,
				code_challenge: "abc123",
				code_challenge_method: "S256",
			});

			expect(result.code_challenge).toBe("abc123");
			expect(result.code_challenge_method).toBe("S256");
		});

		it("stores code_challenge and code_challenge_method in Redis", async () => {
			const result = await repo.createCode({
				...minimalParams,
				code_challenge: "challenge-value",
				code_challenge_method: "S256",
			});

			const stored = store.get(`${KEY_PREFIX}${result.code}`);
			expect(stored).toBeDefined();
			const parsed = JSON.parse(stored as string);
			expect(parsed.code_challenge).toBe("challenge-value");
			expect(parsed.code_challenge_method).toBe("S256");
		});

		it("uses default expiresIn when not provided", async () => {
			const result = await repo.createCode(minimalParams);
			expect(result.expiresIn).toBe(600);
		});

		it("uses provided expiresIn", async () => {
			const result = await repo.createCode({ ...minimalParams, expiresIn: 300 });
			expect(result.expiresIn).toBe(300);
		});
	});

	describe("getByCode", () => {
		it("returns stored code data", async () => {
			const created = await repo.createCode({
				...minimalParams,
				code_challenge: "test-challenge",
				code_challenge_method: "S256",
			});

			const found = await repo.getByCode(created.code);

			expect(found).not.toBeNull();
			expect(found?.code).toBe(created.code);
			expect(found?.code_challenge).toBe("test-challenge");
			expect(found?.code_challenge_method).toBe("S256");
		});

		it("returns null for unknown code", async () => {
			const result = await repo.getByCode("nonexistent-code");
			expect(result).toBeNull();
		});

		it("returns null for corrupted data", async () => {
			store.set(`${KEY_PREFIX}corrupted`, "not-valid-json{{{");
			const result = await repo.getByCode("corrupted");
			expect(result).toBeNull();
		});

		// D-1: pre-v0.5.1 records persisted via the old createCode path lacked
		// `client_id` / `redirect_uri` because RedisCodeRepository.createCode
		// silently dropped both. parseCodeValue treats such records as corrupt
		// (returns null + structured error log) so the strict identity gates
		// in /token never see `client_id: undefined` or `redirect_uri: undefined`.
		it("treats pre-v0.5.1 records lacking client_id and redirect_uri as corrupt", async () => {
			store.set(`${KEY_PREFIX}legacy-1`, JSON.stringify({ code_challenge: "x" }));
			expect(await repo.getByCode("legacy-1")).toBeNull();
		});

		it("treats records with non-string client_id as corrupt", async () => {
			store.set(
				`${KEY_PREFIX}legacy-2`,
				JSON.stringify({ client_id: 123, redirect_uri: "https://rp/cb" }),
			);
			expect(await repo.getByCode("legacy-2")).toBeNull();
		});

		it("treats records with missing redirect_uri as corrupt even if client_id is present", async () => {
			store.set(`${KEY_PREFIX}legacy-3`, JSON.stringify({ client_id: "client-1" }));
			expect(await repo.getByCode("legacy-3")).toBeNull();
		});
	});

	describe("consumeByCode", () => {
		it("returns code data and removes it atomically", async () => {
			const created = await repo.createCode({
				...minimalParams,
				code_challenge: "consume-test",
				code_challenge_method: "S256",
			});

			const consumed = await repo.consumeByCode(created.code);
			expect(consumed).not.toBeNull();
			expect(consumed?.code).toBe(created.code);
			expect(consumed?.code_challenge).toBe("consume-test");

			// Should be gone from store
			expect(store.has(`${KEY_PREFIX}${created.code}`)).toBe(false);
		});

		it("returns null for unknown code", async () => {
			expect(await repo.consumeByCode("nonexistent")).toBeNull();
		});

		it("second consume returns null (replay prevention)", async () => {
			const created = await repo.createCode(minimalParams);
			const first = await repo.consumeByCode(created.code);
			expect(first).not.toBeNull();

			const second = await repo.consumeByCode(created.code);
			expect(second).toBeNull();
		});
	});

	describe("removeByCode", () => {
		it("removes a stored code", async () => {
			const created = await repo.createCode({ ...minimalParams, code_challenge: "c" });
			expect(store.has(`${KEY_PREFIX}${created.code}`)).toBe(true);

			await repo.removeByCode(created.code);
			expect(store.has(`${KEY_PREFIX}${created.code}`)).toBe(false);
		});

		it("does not throw for unknown code", async () => {
			await expect(repo.removeByCode("nonexistent")).resolves.toBeUndefined();
		});
	});

	// D-1 / TD-1 / IH-2 / TS-1: extended-fields round-trip
	// Pre-fix RedisCodeRepository.createCode silently drops every field except
	// code_challenge / code_challenge_method / expiresIn (sid / nonce / redirect_uri /
	// grantedScope / grantedAudience). Production deployments using Redis +
	// userSessionStore could not complete a single authorization-code exchange
	// because codeData.sid was always undefined.
	describe("D-1 extended fields round-trip", () => {
		it("persists and returns client_id, redirect_uri via consumeByCode", async () => {
			const result = await repo.createCode({
				client_id: "client-abc",
				redirect_uri: "https://rp.example/cb",
			});
			const consumed = await repo.consumeByCode(result.code);
			expect(consumed?.client_id).toBe("client-abc");
			expect(consumed?.redirect_uri).toBe("https://rp.example/cb");
		});

		it("persists and returns sid, nonce, grantedScope, grantedAudience via consumeByCode", async () => {
			const result = await repo.createCode({
				client_id: "client-abc",
				redirect_uri: "https://rp.example/cb",
				sid: "sid-xyz",
				nonce: "nonce-abc",
				grantedScope: ["openid", "profile"],
				grantedAudience: ["api.example"],
			});
			const consumed = await repo.consumeByCode(result.code);
			expect(consumed?.sid).toBe("sid-xyz");
			expect(consumed?.nonce).toBe("nonce-abc");
			expect(consumed?.grantedScope).toEqual(["openid", "profile"]);
			expect(consumed?.grantedAudience).toEqual(["api.example"]);
		});

		it("persists all fields in the Redis JSON payload (storage-level assertion)", async () => {
			const result = await repo.createCode({
				client_id: "client-abc",
				redirect_uri: "https://rp.example/cb",
				sid: "sid-xyz",
				nonce: "nonce-abc",
				grantedScope: ["openid"],
			});
			const raw = store.get(`${KEY_PREFIX}${result.code}`) as string;
			expect(raw).toBeDefined();
			const parsed = JSON.parse(raw);
			expect(parsed.client_id).toBe("client-abc");
			expect(parsed.redirect_uri).toBe("https://rp.example/cb");
			expect(parsed.sid).toBe("sid-xyz");
			expect(parsed.nonce).toBe("nonce-abc");
			expect(parsed.grantedScope).toEqual(["openid"]);
		});

		it("getByCode also returns all extended fields", async () => {
			const result = await repo.createCode({
				client_id: "client-abc",
				redirect_uri: "https://rp.example/cb",
				sid: "sid-xyz",
				nonce: "nonce-abc",
			});
			const found = await repo.getByCode(result.code);
			expect(found?.client_id).toBe("client-abc");
			expect(found?.redirect_uri).toBe("https://rp.example/cb");
			expect(found?.sid).toBe("sid-xyz");
			expect(found?.nonce).toBe("nonce-abc");
		});
	});
});
