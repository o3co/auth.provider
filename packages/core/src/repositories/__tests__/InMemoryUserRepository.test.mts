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

	describe("findSubjectByFederatedIdentity (#593, D7 check 5; #611)", () => {
		// The contract is a complete answer about ownership — linked to one
		// user, or established as linked to nobody — or an admission that it
		// cannot tell. This repository keys links by federation name and `sub`
		// and knows nothing of which registration a name is, or which other
		// registrations of the same IdP a person signed in through. So it can
		// establish neither answer, and says so, even where a name-and-sub
		// entry matches: a hit under one registration does not show that no
		// other registration's link names somebody else (#611).
		const registration = {
			provider: "okta",
			issuer: "https://okta.example",
			clientId: "grants-client",
		};
		const repo = () =>
			new InMemoryUserRepository(
				new Map([
					["alice", { password: "x", id: "u1" }],
					["bob", { password: "y", id: "u2", token: "okta:00u-bob" }],
				]),
			);

		it("declares that it covers no registration", () => {
			const r = repo();
			expect(r.supportsFederatedIdentityLookup(registration)).toBe(false);
			expect(r.supportsFederatedIdentityLookup({ ...registration, provider: "google" })).toBe(
				false,
			);
		});

		it("cannot tell, for an identity linked to somebody and for one linked to nobody alike", async () => {
			const r = repo();
			for (const sub of ["00u-bob", "00u-nobody"]) {
				expect(
					await r.findSubjectByFederatedIdentity({ ...registration, sub, claims: {} }),
				).toEqual({
					kind: "indeterminate",
					reason: "registration_not_covered",
				});
			}
		});

		it("changes nothing: a lookup is not a login, a link, or a provisioning", async () => {
			const r = repo();
			await r.findSubjectByFederatedIdentity({ ...registration, sub: "00u-dave", claims: {} });
			expect(await r.authenticateByToken("okta:00u-dave")).toBeNull();
			expect(
				await r.linkFederatedIdentity("u2", {
					provider: "okta",
					sub: "00u-dave",
					token: "okta:00u-dave",
					claims: {},
				}),
			).toMatchObject({ ok: true });
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
