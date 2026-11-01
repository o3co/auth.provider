import { describe, expect, it } from "vitest";
import { type LedgerCall, usersLedger } from "../src/contract.ts";

const alice = {
	identifier: "alice",
	password: "right",
	subject: "u-1",
	email: "a@x.example",
	emailVerified: true,
	upstream: { idp: "corp", subject: "up-1" },
};

/** A lookup's answer for a user it does not know, saying so. */
const notFound = { status: 404, json: { error: "not_found" } };

describe("a fake ledger speaking users-http's calls", () => {
	const ledger = usersLedger([alice]);
	const call = (path: string, body: unknown, credential = ledger.credential): LedgerCall => ({
		method: "POST",
		path,
		headers: { authorization: `Bearer ${credential}` },
		body: JSON.stringify(body),
	});

	it("serves its calls at one origin, under a credential of its own", () => {
		expect(ledger.urls("http://127.0.0.1:1")).toEqual({
			verify: "http://127.0.0.1:1/verify",
			subject: "http://127.0.0.1:1/subject",
			upstream: "http://127.0.0.1:1/upstream",
		});
		expect(ledger.credential).toMatch(/^[0-9a-f]{64}$/);
	});

	it("verifies the right password, and looks a user up by subject, in the shape users-http reads", () => {
		const user = { id: "u-1", username: "alice", email: "a@x.example", emailVerified: true };
		expect(ledger.answer(call("/verify", { email: "alice", password: "right" }))).toEqual({
			json: user,
		});
		expect(ledger.answer(call("/verify", { email: "alice", password: "wrong" }))).toEqual({
			status: 401,
		});
		expect(ledger.answer(call("/subject", { subject: "u-1" }))).toEqual({ json: user });
		expect(ledger.answer(call("/subject", { subject: "u-2" }))).toEqual(notFound);
	});

	it("looks a user up by upstream identity, the IdP and its subject both matching", () => {
		const user = { id: "u-1", username: "alice", email: "a@x.example", emailVerified: true };
		expect(ledger.answer(call("/upstream", { idp: "corp", subject: "up-1" }))).toEqual({
			json: user,
		});
		expect(ledger.answer(call("/upstream", { idp: "other", subject: "up-1" }))).toEqual(notFound);
		expect(ledger.answer(call("/upstream", { idp: "corp", subject: "u-1" }))).toEqual(notFound);
	});

	it("answers a bare 404 to its calls without its credential, which says no user is not known, and nothing to a call not its own", () => {
		expect(ledger.answer(call("/verify", { email: "alice", password: "right" }, "other"))).toEqual({
			status: 404,
		});
		expect(ledger.answer(call("/elsewhere", {}))).toBeUndefined();
	});
});
