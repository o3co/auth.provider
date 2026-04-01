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
import bcrypt from "bcrypt";
import { describe, expect, it } from "vitest";
import { StaticUserRepository } from "../StaticUserRepository.mjs";

describe("StaticUserRepository", () => {
	describe("authenticate", () => {
		it("returns user for valid credentials (plain text)", async () => {
			const repo = new StaticUserRepository(
				new Map([
					["alice", { password: "secret123", id: "u1", email: "alice@example.com" }],
				]),
			);
			const user = await repo.authenticate("alice", "secret123");

			expect(user).not.toBeNull();
			expect(user?.id).toBe("u1");
			expect(user?.username).toBe("alice");
			expect(user?.email).toBe("alice@example.com");
		});

		it("returns null for wrong password", async () => {
			const repo = new StaticUserRepository(
				new Map([["alice", { password: "secret123", id: "u1" }]]),
			);
			const user = await repo.authenticate("alice", "wrong");

			expect(user).toBeNull();
		});

		it("returns null for unknown username", async () => {
			const repo = new StaticUserRepository(
				new Map([["alice", { password: "secret123", id: "u1" }]]),
			);
			const user = await repo.authenticate("bob", "secret123");

			expect(user).toBeNull();
		});

		it("supports bcrypt hashed passwords", async () => {
			const hash = await bcrypt.hash("secret123", 10);
			const repo = new StaticUserRepository(
				new Map([["alice", { password: hash, id: "u1" }]]),
			);
			const user = await repo.authenticate("alice", "secret123");

			expect(user).not.toBeNull();
			expect(user?.username).toBe("alice");
		});

		it("does not include password in returned user", async () => {
			const repo = new StaticUserRepository(
				new Map([["alice", { password: "secret123", id: "u1" }]]),
			);
			const user = await repo.authenticate("alice", "secret123");

			expect(user).not.toBeNull();
			expect((user as Record<string, unknown>).password).toBeUndefined();
		});
	});

	describe("authenticateByToken", () => {
		it("returns user matching token field", async () => {
			const repo = new StaticUserRepository(
				new Map([["alice", { password: "secret123", id: "u1", token: "tok_alice_123" }]]),
			);
			const user = await repo.authenticateByToken("tok_alice_123");

			expect(user).not.toBeNull();
			expect(user?.username).toBe("alice");
		});

		it("returns null when no user has matching token", async () => {
			const repo = new StaticUserRepository(
				new Map([["alice", { password: "secret123", id: "u1", token: "tok_alice_123" }]]),
			);
			const user = await repo.authenticateByToken("tok_unknown");

			expect(user).toBeNull();
		});

		it("returns null when no users have token field", async () => {
			const repo = new StaticUserRepository(
				new Map([["alice", { password: "secret123", id: "u1" }]]),
			);
			const user = await repo.authenticateByToken("tok_anything");

			expect(user).toBeNull();
		});
	});
});
