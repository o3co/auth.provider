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
	it("are held by a ledger unless one has an upstream link or a bcrypt hash", () => {
		expect(unledgered([alice])).toBeUndefined();
		const linked = { ...alice, upstream: { idp: "corp", subject: "u" } };
		expect(unledgered([linked, { ...alice, bcrypt: true }])).toBe(
			"gives users a ledger cannot hold: upstream links, a password hash other than scrypt",
		);
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
		const ledger = await ledgerParty([alice]);
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
		const ledger = await ledgerParty([alice]);
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
		const ledger = await ledgerParty([bob, carol]);
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
