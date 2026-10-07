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
import { describe, expect, it, type MockInstance, vi } from "vitest";
import { InMemoryUserRepository, UserEntrySchema } from "#/repositories/InMemoryUserRepository.mjs";

/** A spy on `bcrypt.compare`'s promise overload; `vi.spyOn` alone types it by the callback one, which returns `void`. */
const spyOnCompare = () =>
	vi.spyOn(bcrypt, "compare") as unknown as MockInstance<
		(data: string | Buffer, encrypted: string) => Promise<boolean>
	>;

/** A bcrypt body (22-character salt and 31-character hash) in bcrypt's alphabet. */
const BODY = "39.FBAWt.ck.rbQbPhmLOOPkwFxWEPZEYA3HR07Lr2k5OYqk.vRSi";

/** A well-formed bcrypt hash of `prefix` at `cost`; it is the hash of no known password. */
const shaped = (cost: string, prefix = "$2b$"): string => `${prefix}${cost}$${BODY}`;

/** What the schema says of `entry`, as `loadYamlMap` reports it: each issue's path and message. */
const issuesOf = (entry: unknown): string[] => {
	const result = UserEntrySchema.safeParse(entry);
	return result.success ? [] : result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
};

/** The message the repository refuses `users` with, or `undefined` when it holds them. */
const refusalOf = (users: Map<string, Record<string, unknown>>): string | undefined => {
	try {
		new InMemoryUserRepository(users as never);
		return undefined;
	} catch (err) {
		return (err as Error).message;
	}
};

describe("InMemoryUserRepository", () => {
	describe("the entries it holds", () => {
		it("holds a well-formed $2a$, $2b$ or $2y$ hash at a cost from 04 to 15", () => {
			for (const password of [
				shaped("10", "$2a$"),
				shaped("10", "$2b$"),
				shaped("10", "$2y$"),
				shaped("04"),
				shaped("15"),
			]) {
				expect(issuesOf({ password }), password).toEqual([]);
				expect(refusalOf(new Map([["alice", { password }]])), password).toBeUndefined();
			}
		});

		it("refuses a value shaped as a bcrypt hash that is not a well-formed one, naming the user and the field and never the value", () => {
			for (const password of [
				`$2b$10$${BODY.slice(1)}`, // a 52-character body
				`$2b$10$${BODY}x`, // a 54-character body
				`$2b$10$${BODY.slice(1)}!`, // a character outside bcrypt's alphabet
				`$2b$10$${BODY.slice(1)}+`, // base64's alphabet, not bcrypt's
				`$2b$9$${BODY}`, // a one-digit cost
				`$2b$100$${BODY}`, // a three-digit cost
				`$2b$1a$${BODY}`, // a cost that is not a number
				`$2b$10${BODY}`, // no separator after the cost
				"$2b$10$", // no body
				"$2b$",
			]) {
				const issues = issuesOf({ password });
				expect(issues, password).toHaveLength(1);
				expect(issues[0], password).toMatch(/^password: .*well-formed bcrypt hash/);
				const refusal = refusalOf(new Map([["alice", { password }]]));
				expect(refusal, password).toMatch(/"alice"/);
				expect(refusal, password).toMatch(/password: /);
				expect(refusal, password).not.toContain(BODY.slice(1, 40));
			}
		});

		it("refuses a cost below bcrypt's least, 04, and above 31, which bcrypt never computes", () => {
			for (const cost of ["03", "00", "32", "99"]) {
				expect(issuesOf({ password: shaped(cost) }), cost).toEqual([
					"password: the bcrypt cost must be from 04 to 15",
				]);
			}
		});

		it("refuses a cost above the ceiling, 15", () => {
			expect(issuesOf({ password: shaped("15") })).toEqual([]);
			for (const cost of ["16", "20", "31"]) {
				expect(issuesOf({ password: shaped(cost) }), cost).toEqual([
					"password: the bcrypt cost must be from 04 to 15",
				]);
				expect(refusalOf(new Map([["alice", { password: shaped(cost) }]]))).toMatch(
					/"alice".*password: the bcrypt cost must be from 04 to 15/,
				);
			}
		});

		it("refuses a value starting with $2 that is no supported bcrypt form: $2$, $2x$ and any other", () => {
			for (const password of [`$2$10$${BODY}`, shaped("10", "$2x$"), shaped("10", "$2c$"), "$2"]) {
				const issues = issuesOf({ password });
				expect(issues, password).toHaveLength(1);
				expect(issues[0], password).toMatch(/^password: .*\$2a\$, \$2b\$ and \$2y\$/);
				expect(refusalOf(new Map([["alice", { password }]])), password).toMatch(/"alice"/);
			}
		});

		it("holds a plain-text password that does not start with $2", () => {
			for (const password of ["secret123", "$1$abc", "2b$10$", "$$2b$"]) {
				expect(issuesOf({ password }), password).toEqual([]);
			}
		});

		it("refuses an empty id", () => {
			expect(issuesOf({ password: "secret123", id: "" })).toEqual([expect.stringMatching(/^id: /)]);
			expect(refusalOf(new Map([["alice", { password: "secret123", id: "" }]]))).toMatch(
				/"alice".*id: /,
			);
		});

		it("refuses two users with the same id, whether written or taken from a username, naming both users", () => {
			for (const users of [
				new Map([
					["alice", { password: "a", id: "u1" }],
					["bob", { password: "b", id: "u1" }],
				]),
				new Map([
					["alice", { password: "a", id: "bob" }],
					["bob", { password: "b" }],
				]),
			]) {
				const refusal = refusalOf(users);
				expect(refusal).toMatch(/"alice" and "bob"/);
				expect(refusal).toMatch(/\bid\b/);
			}
			expect(
				refusalOf(
					new Map([
						["alice", { password: "a", id: "u1" }],
						["bob", { password: "b" }],
					]),
				),
			).toBeUndefined();
		});

		it("refuses bcrypt entries at more than one cost, naming the field and the costs", () => {
			for (const [costs, named] of [
				[["10", "12"], "costs 10 and 12"],
				[["12", "04", "10", "12"], "costs 04, 10 and 12"],
			] as const) {
				const users = new Map<string, Record<string, unknown>>(
					costs.map((cost, i) => [`user${i}`, { password: shaped(cost, i % 2 ? "$2y$" : "$2b$") }]),
				);
				users.set("plain", { password: "plain-text" });
				const refusal = refusalOf(users);
				expect(refusal, named).toMatch(
					new RegExp(`password: bcrypt entries use ${named}; every bcrypt entry must use one cost`),
				);
				expect(refusal, named).not.toContain(BODY.slice(0, 20));
			}
		});

		it("holds bcrypt entries at one cost beside plain-text ones", () => {
			expect(
				refusalOf(
					new Map([
						["alice", { password: shaped("12") }],
						["bob", { password: shaped("12", "$2a$") }],
						["carol", { password: "plain-text" }],
					]),
				),
			).toBeUndefined();
		});

		it("refuses an empty username, which would be an empty id, naming the field", () => {
			for (const entry of [{ password: "plain" }, { password: "plain", id: "u1" }]) {
				const refusal = refusalOf(new Map([["", entry]]));
				expect(refusal, JSON.stringify(entry)).toMatch(/username/);
				expect(refusal, JSON.stringify(entry)).not.toContain("plain");
			}
		});

		it("refuses a username key in an entry: the entry's key is its username", () => {
			for (const username of ["bob", "alice"]) {
				expect(issuesOf({ password: "secret123", username })).toEqual([
					expect.stringMatching(/^username: /),
				]);
				const refusal = refusalOf(new Map([["alice", { password: "secret123", username }]]));
				expect(refusal).toMatch(/"alice".*username: /);
			}
		});
	});

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
			const compareSpy = spyOnCompare().mockResolvedValue(false);
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
			const compareSpy = spyOnCompare().mockResolvedValue(false);
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

		it("compares a $2y$ hash as the $2b$ hash it is", async () => {
			// What `htpasswd -nbB -C 10 alice 'correct horse'` writes.
			const hash = "$2y$10$4uWAsJ6MNCcwoAr7IN2fyONLhHeOLmjfrS8J/Aaq3EUpUpbavVeSO";
			const repo = new InMemoryUserRepository(new Map([["alice", { password: hash, id: "u1" }]]));

			expect((await repo.authenticate("alice", "correct horse"))?.id).toBe("u1");
			expect(await repo.authenticate("alice", "correct horsE")).toBeNull();
		});

		it("pays the unknown-user and plain-text compares at the entries' one cost", async () => {
			const compareSpy = spyOnCompare().mockResolvedValue(false);
			const dummyCostFor = async (
				users: Map<string, { password: string }>,
				username: string,
			): Promise<string | undefined> => {
				compareSpy.mockClear();
				await new InMemoryUserRepository(users).authenticate(username, "wrong");
				return compareSpy.mock.calls[0]?.[1]?.slice(0, 7);
			};
			try {
				const atTwelve = new Map([
					["alice", { password: shaped("12") }],
					["bob", { password: shaped("12", "$2y$") }],
					["carol", { password: "plain" }],
				]);
				expect(await dummyCostFor(atTwelve, "nobody")).toBe("$2b$12$");
				expect(await dummyCostFor(atTwelve, "carol")).toBe("$2b$12$");
				expect(await dummyCostFor(new Map([["alice", { password: shaped("04") }]]), "nobody")).toBe(
					"$2b$04$",
				);
				// No bcrypt entry: the cost bcrypt's own default and this file's examples use.
				expect(await dummyCostFor(new Map([["alice", { password: "plain" }]]), "nobody")).toBe(
					"$2b$10$",
				);
				expect(await dummyCostFor(new Map(), "nobody")).toBe("$2b$10$");
			} finally {
				compareSpy.mockRestore();
			}
		});

		it("runs the unknown-user and plain-text compares through bcrypt at the cost of the entries' real hashes", async () => {
			const compareSpy = spyOnCompare();
			try {
				const repo = new InMemoryUserRepository(
					new Map([
						["alice", { password: await bcrypt.hash("alice-pass", 4) }],
						["bob", { password: await bcrypt.hash("bob-pass", 4) }],
						["carol", { password: "carol-pass" }],
					]),
				);

				expect(await repo.authenticate("nobody", "alice-pass")).toBeNull();
				expect(await repo.authenticate("carol", "carol-pass")).not.toBeNull();
				expect((await repo.authenticate("bob", "bob-pass"))?.username).toBe("bob");

				const [unknownUser, plainText, known] = compareSpy.mock.calls.map(([, hash]) => hash);
				// bcrypt reads the cost it then runs at from the hash it is handed.
				expect(bcrypt.getRounds(unknownUser as string)).toBe(4);
				expect(bcrypt.getRounds(plainText as string)).toBe(4);
				expect(bcrypt.getRounds(known as string)).toBe(4);
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

	describe("findSubjectByFederatedIdentity", () => {
		// The contract is a complete answer about ownership — linked to one
		// user, or established as linked to nobody — or an admission that it
		// cannot tell. This repository keys links by federation name and `sub`
		// and knows nothing of which registration a name is, or which other
		// registrations of the same IdP a person signed in through. So it can
		// establish neither answer, and says so, even where a name-and-sub
		// entry matches: a hit under one registration does not show that no
		// other registration's link names somebody else.
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
			expect(r.supportsFederatedIdentityLookup(registration, ["sub"])).toBe(false);
			expect(
				r.supportsFederatedIdentityLookup({ ...registration, provider: "google" }, ["sub"]),
			).toBe(false);
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

	describe("linkFederatedIdentity", () => {
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
