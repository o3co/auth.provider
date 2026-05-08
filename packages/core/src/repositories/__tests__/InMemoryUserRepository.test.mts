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
import { describe, expect, it, vi } from "vitest";
import { InMemoryUserRepository } from "#/repositories/InMemoryUserRepository.mjs";

describe("InMemoryUserRepository", () => {
	describe("authenticate", () => {
		it("returns user for valid credentials (plain text)", async () => {
			const repo = new InMemoryUserRepository(
				new Map([["alice", { password: "secret123", id: "u1", email: "alice@example.com" }]]),
			);
			const user = await repo.authenticate("alice", "secret123");

			expect(user).not.toBeNull();
			expect(user?.id).toBe("u1");
			expect(user?.username).toBe("alice");
			expect(user?.email).toBe("alice@example.com");
		});

		it("returns null for wrong password", async () => {
			const repo = new InMemoryUserRepository(
				new Map([["alice", { password: "secret123", id: "u1" }]]),
			);
			const user = await repo.authenticate("alice", "wrong");

			expect(user).toBeNull();
		});

		it("returns null for unknown username", async () => {
			const repo = new InMemoryUserRepository(
				new Map([["alice", { password: "secret123", id: "u1" }]]),
			);
			const user = await repo.authenticate("bob", "secret123");

			expect(user).toBeNull();
		});

		it("runs a dummy bcrypt compare for unknown usernames", async () => {
			const compareSpy = vi.spyOn(bcrypt, "compare").mockResolvedValue(false);
			// Use a hash deliberately distinct from the source's dummy hash so
			// the regression assertion below can verify the unknown-user path
			// uses a different bcrypt input than the real entry.
			const hash = await bcrypt.hash("secret123", 10);
			const repo = new InMemoryUserRepository(new Map([["alice", { password: hash, id: "u1" }]]));
			try {
				const [wrongPassword, unknownUser] = await Promise.all([
					repo.authenticate("alice", "wrong"),
					repo.authenticate("bob", "wrong"),
				]);

				expect(wrongPassword).toBeNull();
				expect(unknownUser).toBeNull();
				expect(compareSpy).toHaveBeenCalledTimes(2);
				const realCall = compareSpy.mock.calls[0];
				const dummyCall = compareSpy.mock.calls[1];
				expect(realCall?.[0]).toBe("wrong");
				expect(realCall?.[1]).toBe(hash);
				expect(dummyCall?.[0]).toBe("wrong");
				expect(dummyCall?.[1]).toMatch(/^\$2[aby]\$/);
				// Unknown-user path MUST use a hash distinct from the real entry's
				// hash — otherwise timingSafeEqual on the bcrypt result would still
				// leak username existence on a single targeted user.
				expect(dummyCall?.[1]).not.toBe(hash);
			} finally {
				compareSpy.mockRestore();
			}
		});

		it("runs a bcrypt compare on the plain-text path to equalize timing", async () => {
			const compareSpy = vi.spyOn(bcrypt, "compare").mockResolvedValue(false);
			const repo = new InMemoryUserRepository(
				new Map([["alice", { password: "secret123", id: "u1" }]]),
			);
			try {
				const [knownPlain, unknownUser] = await Promise.all([
					repo.authenticate("alice", "wrong"),
					repo.authenticate("bob", "wrong"),
				]);

				expect(knownPlain).toBeNull();
				expect(unknownUser).toBeNull();
				// Both paths must call bcrypt.compare so that plain-text and
				// unknown-user cases converge on the same cost. Without this,
				// plain-text deployments leak username existence via timing.
				expect(compareSpy).toHaveBeenCalledTimes(2);
				for (const call of compareSpy.mock.calls) {
					expect(call?.[1]).toMatch(/^\$2[aby]\$/);
				}
			} finally {
				compareSpy.mockRestore();
			}
		});

		it("supports bcrypt hashed passwords", async () => {
			const hash = await bcrypt.hash("secret123", 10);
			const repo = new InMemoryUserRepository(new Map([["alice", { password: hash, id: "u1" }]]));
			const user = await repo.authenticate("alice", "secret123");

			expect(user).not.toBeNull();
			expect(user?.username).toBe("alice");
		});

		it("does not include password in returned user", async () => {
			const repo = new InMemoryUserRepository(
				new Map([["alice", { password: "secret123", id: "u1" }]]),
			);
			const user = await repo.authenticate("alice", "secret123");

			expect(user).not.toBeNull();
			expect((user as Record<string, unknown>).password).toBeUndefined();
		});
	});

	describe("authenticateByToken", () => {
		it("returns user matching token field", async () => {
			const repo = new InMemoryUserRepository(
				new Map([["alice", { password: "secret123", id: "u1", token: "tok_alice_123" }]]),
			);
			const user = await repo.authenticateByToken("tok_alice_123");

			expect(user).not.toBeNull();
			expect(user?.username).toBe("alice");
		});

		it("returns null when no user has matching token", async () => {
			const repo = new InMemoryUserRepository(
				new Map([["alice", { password: "secret123", id: "u1", token: "tok_alice_123" }]]),
			);
			const user = await repo.authenticateByToken("tok_unknown");

			expect(user).toBeNull();
		});

		it("returns null when no users have token field", async () => {
			const repo = new InMemoryUserRepository(
				new Map([["alice", { password: "secret123", id: "u1" }]]),
			);
			const user = await repo.authenticateByToken("tok_anything");

			expect(user).toBeNull();
		});
	});
});
