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
import { afterEach, describe, expect, it } from "vitest";
import { InMemoryCodeRepository } from "../InMemoryCodeRepository.mjs";

describe("InMemoryCodeRepository", () => {
	let repo: InMemoryCodeRepository;

	afterEach(() => {
		repo?.dispose();
	});

	describe("createCode", () => {
		it("creates a code with random string", async () => {
			repo = new InMemoryCodeRepository();
			const code = await repo.createCode({});

			expect(code.code).toBeDefined();
			expect(typeof code.code).toBe("string");
			expect(code.code.length).toBeGreaterThan(0);
		});

		it("stores code_challenge and code_challenge_method", async () => {
			repo = new InMemoryCodeRepository();
			const code = await repo.createCode({
				code_challenge: "challenge123",
				code_challenge_method: "S256",
			});

			expect(code.code_challenge).toBe("challenge123");
			expect(code.code_challenge_method).toBe("S256");
		});

		it("generates unique codes", async () => {
			repo = new InMemoryCodeRepository();
			const codes = await Promise.all(Array.from({ length: 10 }, () => repo.createCode({})));
			const unique = new Set(codes.map((c) => c.code));
			expect(unique.size).toBe(10);
		});
	});

	describe("getByCode", () => {
		it("returns stored code", async () => {
			repo = new InMemoryCodeRepository();
			const created = await repo.createCode({ code_challenge: "ch" });
			const found = await repo.getByCode(created.code);

			expect(found).not.toBeNull();
			expect(found?.code).toBe(created.code);
			expect(found?.code_challenge).toBe("ch");
		});

		it("returns null for unknown code", async () => {
			repo = new InMemoryCodeRepository();
			const found = await repo.getByCode("nonexistent");

			expect(found).toBeNull();
		});
	});

	describe("consumeByCode", () => {
		it("returns and removes the code atomically", async () => {
			repo = new InMemoryCodeRepository();
			const created = await repo.createCode({});
			const consumed = await repo.consumeByCode(created.code);

			expect(consumed).not.toBeNull();
			expect(consumed?.code).toBe(created.code);

			// Second consume returns null (replay prevention)
			const again = await repo.consumeByCode(created.code);
			expect(again).toBeNull();
		});

		it("returns null for unknown code", async () => {
			repo = new InMemoryCodeRepository();
			const consumed = await repo.consumeByCode("nonexistent");

			expect(consumed).toBeNull();
		});
	});

	describe("removeByCode", () => {
		it("removes a stored code", async () => {
			repo = new InMemoryCodeRepository();
			const created = await repo.createCode({});
			await repo.removeByCode(created.code);

			const found = await repo.getByCode(created.code);
			expect(found).toBeNull();
		});

		it("does not throw for unknown code", async () => {
			repo = new InMemoryCodeRepository();
			await expect(repo.removeByCode("nonexistent")).resolves.toBeUndefined();
		});
	});

	describe("expiration", () => {
		it("expires codes after defaultExpiresIn", async () => {
			repo = new InMemoryCodeRepository({ defaultExpiresIn: 0.05 }); // 50ms
			const created = await repo.createCode({});

			await new Promise((r) => setTimeout(r, 100));

			const found = await repo.getByCode(created.code);
			expect(found).toBeNull();
		});

		it("respects per-code expiresIn override", async () => {
			repo = new InMemoryCodeRepository({ defaultExpiresIn: 10 });
			const created = await repo.createCode({ expiresIn: 0.05 }); // 50ms

			await new Promise((r) => setTimeout(r, 100));

			const found = await repo.getByCode(created.code);
			expect(found).toBeNull();
		});
	});
});
