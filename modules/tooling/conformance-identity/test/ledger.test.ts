import { describe, expect, it } from "vitest";
import { ledgerParty, unledgered } from "../src/ledger.ts";
import { onPattern } from "../src/new.ts";

const alice = {
	identifier: "alice",
	password: "right",
	subject: "u-1",
	email: "alice@example.com",
	emailVerified: true,
};

describe("the scene's users on an app taking users from a ledger", () => {
	it("are held by a ledger, upstream links included, unless one has a bcrypt hash", () => {
		expect(unledgered([alice])).toBeUndefined();
		const linked = { ...alice, upstream: { idp: "corp", subject: "u" } };
		expect(unledgered([linked])).toBeUndefined();
		expect(unledgered([linked, { ...alice, bcrypt: true }])).toBe(
			"gives users a ledger cannot hold: a password hash other than scrypt",
		);
	});

	it("are looked up by upstream identity at the ledger, the IdP and its subject both matching", async () => {
		const linked = { ...alice, upstream: { idp: "corp", subject: "up-1" } };
		const ledger = await ledgerParty({ users: [linked] });
		const section = ledger.config["users-http"] ?? {};
		const lookup = (idp: string, subject: string) =>
			fetch(String(section["upstream-url"]), {
				method: "POST",
				headers: { authorization: `Bearer ${section.credential}` },
				body: JSON.stringify({ idp, subject }),
			});
		try {
			expect(section["upstream-url"]).toBe(`${ledger.base}/upstream`);
			expect(await (await lookup("corp", "up-1")).json()).toMatchObject({ id: "u-1" });
			expect((await lookup("other", "up-1")).status).toBe(404);
		} finally {
			await ledger.stop();
		}
	});

	it("leave a scene out where a user is one a ledger cannot hold, and are served by a ledger otherwise", () => {
		const origin = "https://as.example";
		const ledgered = ["@mod/users-http"];
		// Run on a fake ledger that compares passwords itself, a scene about bcrypt would pass without bcrypt.
		expect(onPattern({ origin, users: [{ ...alice, bcrypt: true }] }, {}, ledgered)).toEqual({
			leaveOut: "gives users a ledger cannot hold: a password hash other than scrypt",
		});
		expect(onPattern({ origin, users: [alice] }, {}, ledgered)).toHaveProperty("party");
		expect(onPattern({ origin, users: [{ ...alice, bcrypt: true }] }, {}, [])).not.toHaveProperty(
			"leaveOut",
		);
	});

	it("are looked up by subject at the ledger, none for a subject it does not hold", async () => {
		const ledger = await ledgerParty({ users: [alice] });
		const section = ledger.config["users-http"] ?? {};
		const lookup = (subject: string) =>
			fetch(String(section["subject-url"]), {
				method: "POST",
				headers: { authorization: `Bearer ${section.credential}` },
				body: JSON.stringify({ subject }),
			});
		try {
			expect(section["subject-url"]).toBe(`${ledger.base}/subject`);
			expect(await (await lookup("u-1")).json()).toMatchObject({ id: "u-1", username: "alice" });
			expect((await lookup("u-2")).status).toBe(404);
		} finally {
			await ledger.stop();
		}
	});

	it("are answered by the ledger for the right password and its credential alone", async () => {
		const ledger = await ledgerParty({ users: [alice] });
		const section = ledger.config["users-http"] ?? {};
		const verify = (email: string, password: string, credential = section.credential) =>
			fetch(String(section["verify-url"]), {
				method: "POST",
				headers: { authorization: `Bearer ${credential}` },
				body: JSON.stringify({ email, password }),
			});
		try {
			expect(section["verify-url"]).toBe(`${ledger.base}/verify`);
			expect(await (await verify("alice", "right")).json()).toEqual({
				id: "u-1",
				username: "alice",
				email: "alice@example.com",
				emailVerified: true,
			});
			expect((await verify("alice", "wrong")).status).toBe(401);
			expect((await verify("bob", "right")).status).toBe(401);
			expect((await verify("alice", "right", "other")).status).toBe(404);
		} finally {
			await ledger.stop();
		}
	});

	it("give an address with a stated verification, as users keeps one only beside an address", async () => {
		const bob = { identifier: "bob", password: "right", subject: "u-2", emailVerified: false };
		const carol = { identifier: "carol", password: "right", subject: "u-3" };
		const ledger = await ledgerParty({ users: [bob, carol] });
		const section = ledger.config["users-http"] ?? {};
		const verify = async (email: string) =>
			(
				await fetch(String(section["verify-url"]), {
					method: "POST",
					headers: { authorization: `Bearer ${section.credential}` },
					body: JSON.stringify({ email, password: "right" }),
				})
			).json();
		try {
			expect(await verify("bob")).toEqual({
				id: "u-2",
				username: "bob",
				email: "bob@users.example",
				emailVerified: false,
			});
			expect(await verify("carol")).toEqual({ id: "u-3", username: "carol" });
		} finally {
			await ledger.stop();
		}
	});
});

describe("mfa's witness on an app keeping it at a ledger", () => {
	it("is kept by the ledger, whoever holds the users: a scene with its own ledger too", () => {
		const origin = "https://as.example";
		const witnessed = ["@mod/users-http", "@mod/mfa-witness-http"];
		const own = { verifyUrl: "https://own.example/verify", credential: "c" };
		for (const part of [
			{ origin, users: [alice] },
			{ origin, users: [], ledger: own },
		]) {
			const set = onPattern(part, {}, witnessed);
			expect(set).toHaveProperty("party");
			expect(set).toMatchObject({ whole: expect.arrayContaining(["mfa-witness-http"]) });
		}
		expect(onPattern({ origin, users: [] }, {}, [])).not.toHaveProperty("party");
	});

	it("answers whether a subject is enrolled, takes the first mark, and clears it, with its credential alone", async () => {
		const ledger = await ledgerParty({ witness: true });
		const section = ledger.config["mfa-witness-http"] ?? {};
		const ask = (key: string, body: unknown, credential = section.credential) =>
			fetch(String(section[key]), {
				method: "POST",
				headers: { authorization: `Bearer ${credential}` },
				body: JSON.stringify(body),
			});
		try {
			expect(ledger.config).not.toHaveProperty("users-http");
			for (const key of ["read-url", "enroll-url", "clear-url"]) {
				expect(new URL(String(section[key])).origin, key).toBe(ledger.base);
			}
			expect(await (await ask("read-url", { subject: "u-1" })).json()).toEqual({ enrolled: false });
			expect(await (await ask("enroll-url", { subject: "u-1", token: "a" })).json()).toEqual({
				owner: true,
			});
			expect(await (await ask("enroll-url", { subject: "u-1", token: "b" })).json()).toEqual({
				owner: false,
			});
			expect(await (await ask("read-url", { subject: "u-1" })).json()).toEqual({ enrolled: true });
			expect((await ask("clear-url", { subject: "u-1" })).status).toBe(204);
			expect(await (await ask("read-url", { subject: "u-1" })).json()).toEqual({ enrolled: false });
			expect((await ask("read-url", { subject: "u-1" }, "wrong")).status).toBe(404);
		} finally {
			await ledger.stop();
		}
	});
});
