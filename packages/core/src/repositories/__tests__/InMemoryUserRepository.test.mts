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

	describe("findSubjectByFederatedIdentity (#593, D7 check 5)", () => {
		const repo = () =>
			new InMemoryUserRepository(
				new Map([
					["alice", { password: "x", id: "u1" }],
					["bob", { password: "y", id: "u2", token: "okta:00u-bob" }],
					["carol", { password: "z", token: "okta:00u-carol" }],
				]),
			);

		it("answers the local subject an upstream identity is linked to, configured or linked at runtime", async () => {
			const r = repo();
			expect(await r.findSubjectByFederatedIdentity({ provider: "okta", sub: "00u-bob" })).toBe(
				"u2",
			);
			// No `id` on the entry: the user's id is the username, as authenticateByToken answers.
			expect(await r.findSubjectByFederatedIdentity({ provider: "okta", sub: "00u-carol" })).toBe(
				"carol",
			);
			await r.linkFederatedIdentity("u1", {
				provider: "okta",
				sub: "00u-alice",
				token: "okta:00u-alice",
				claims: {},
			});
			expect(await r.findSubjectByFederatedIdentity({ provider: "okta", sub: "00u-alice" })).toBe(
				"u1",
			);
		});

		it("answers null for an identity linked to nobody, and keys it by the federation's name", async () => {
			const r = repo();
			expect(
				await r.findSubjectByFederatedIdentity({ provider: "okta", sub: "00u-nobody" }),
			).toBeNull();
			expect(
				await r.findSubjectByFederatedIdentity({ provider: "google", sub: "00u-bob" }),
			).toBeNull();
		});

		it("changes nothing: a lookup is not a login, a link, or a provisioning", async () => {
			// The grant callback asks whether an identity already belongs to
			// somebody else. A Store whose lookup stamped a login or linked on
			// first sight would turn that question into an account change.
			const r = repo();
			expect(
				await r.findSubjectByFederatedIdentity({ provider: "okta", sub: "00u-dave" }),
			).toBeNull();
			expect(await r.authenticateByToken("okta:00u-dave")).toBeNull();
			// Nothing was reserved for anyone: the identity can still go to u2.
			expect(
				await r.linkFederatedIdentity("u2", {
					provider: "okta",
					sub: "00u-dave",
					token: "okta:00u-dave",
					claims: {},
				}),
			).toMatchObject({ ok: true });
		});

		it("refuses to choose between two owners of one identity rather than answering the first", async () => {
			// authenticateByToken takes the first match, which is a login's
			// problem. Here the answer decides whether a delegation is refused as
			// somebody else's, and an arbitrary one is worse than an outage.
			const r = new InMemoryUserRepository(
				new Map([
					["erin", { password: "x", id: "u5", token: "okta:00u-shared" }],
					["frank", { password: "y", id: "u6", token: "okta:00u-shared" }],
				]),
			);
			await expect(
				r.findSubjectByFederatedIdentity({ provider: "okta", sub: "00u-shared" }),
			).rejects.toThrow(/more than one/);
		});
	});

	describe("linkFederatedIdentity (#482)", () => {
		const apple = { provider: "apple", sub: "a1", token: "apple:a1", claims: {} };
		const repo = () =>
			new InMemoryUserRepository(
				new Map([
					["alice", { password: "x", id: "u1" }],
					["bob", { password: "y", id: "u2", token: "google:bob-sub" }],
				]),
			);

		it("links a token to a user so authenticateByToken resolves it afterwards", async () => {
			const r = repo();
			expect(await r.authenticateByToken("apple:a1")).toBeNull();
			const out = await r.linkFederatedIdentity("u1", apple);
			expect(out).toMatchObject({ ok: true, user: { id: "u1", username: "alice" } });
			expect((await r.authenticateByToken("apple:a1"))?.id).toBe("u1");
		});

		it("refuses an unknown user, and reports a conflict for a token another user holds", async () => {
			const r = repo();
			expect(await r.linkFederatedIdentity("nobody", apple)).toMatchObject({
				ok: false,
				reason: "refused",
			});
			expect(
				await r.linkFederatedIdentity("u1", {
					provider: "google",
					sub: "bob-sub",
					token: "google:bob-sub",
					claims: {},
				}),
			).toMatchObject({ ok: false, reason: "conflict" });
			// Linking the same identity to the same user twice is fine; to another user it is not.
			await r.linkFederatedIdentity("u1", apple);
			expect(await r.linkFederatedIdentity("u1", apple)).toMatchObject({ ok: true });
			expect(await r.linkFederatedIdentity("u2", apple)).toMatchObject({
				ok: false,
				reason: "conflict",
			});
		});
	});
});
