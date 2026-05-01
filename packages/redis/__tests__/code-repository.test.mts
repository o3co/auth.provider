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

	beforeEach(async () => {
		store.clear();
		const redis = createMockRedis();
		repo = new RedisCodeRepository(redis);
		await repo.initialize();
	});

	describe("createCode", () => {
		it("generates a code string and stores it", async () => {
			const result = await repo.createCode({});

			expect(typeof result.code).toBe("string");
			expect(result.code.length).toBeGreaterThan(0);
			// Verify it was stored with namespace prefix
			expect(store.has(`${KEY_PREFIX}${result.code}`)).toBe(true);
		});

		it("returns code with code_challenge and code_challenge_method", async () => {
			const result = await repo.createCode({
				code_challenge: "abc123",
				code_challenge_method: "S256",
			});

			expect(result.code_challenge).toBe("abc123");
			expect(result.code_challenge_method).toBe("S256");
		});

		it("stores code_challenge and code_challenge_method in Redis", async () => {
			const result = await repo.createCode({
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
			const result = await repo.createCode({});
			expect(result.expiresIn).toBe(600);
		});

		it("uses provided expiresIn", async () => {
			const result = await repo.createCode({ expiresIn: 300 });
			expect(result.expiresIn).toBe(300);
		});
	});

	describe("getByCode", () => {
		it("returns stored code data", async () => {
			const created = await repo.createCode({
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
	});

	describe("consumeByCode", () => {
		it("returns code data and removes it atomically", async () => {
			const created = await repo.createCode({
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
			const created = await repo.createCode({});
			const first = await repo.consumeByCode(created.code);
			expect(first).not.toBeNull();

			const second = await repo.consumeByCode(created.code);
			expect(second).toBeNull();
		});
	});

	describe("removeByCode", () => {
		it("removes a stored code", async () => {
			const created = await repo.createCode({ code_challenge: "c" });
			expect(store.has(`${KEY_PREFIX}${created.code}`)).toBe(true);

			await repo.removeByCode(created.code);
			expect(store.has(`${KEY_PREFIX}${created.code}`)).toBe(false);
		});

		it("does not throw for unknown code", async () => {
			await expect(repo.removeByCode("nonexistent")).resolves.toBeUndefined();
		});
	});
});
