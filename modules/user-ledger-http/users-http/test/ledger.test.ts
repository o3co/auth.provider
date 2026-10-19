import { describe, expect, it } from "vitest";
import { type LedgerCall, usersLedger } from "../src/testing.ts";

const alice = {
	identifier: "alice",
	password: "right",
	subject: "u-1",
	email: "a@x.example",
	emailVerified: true,
	upstream: { idp: "corp", subject: "up-1" },
};

describe("a fake ledger speaking users-http's calls", () => {
	const ledger = usersLedger([alice]);
	const section = ledger.section("http://127.0.0.1:1")["users-http"];
	const call = (path: string, body: unknown, credential = section.credential): LedgerCall => ({
		method: "POST",
		path,
		headers: { authorization: `Bearer ${credential}` },
		body: JSON.stringify(body),
	});

	it("points users-http at its calls, under a credential of its own", () => {
		expect(section).toEqual({
			"verify-url": "http://127.0.0.1:1/verify",
			"subject-url": "http://127.0.0.1:1/subject",
			"upstream-url": "http://127.0.0.1:1/upstream",
			credential: expect.stringMatching(/^[0-9a-f]{64}$/),
		});
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
		expect(ledger.answer(call("/subject", { subject: "u-2" }))).toEqual({ status: 404 });
	});

	it("looks a user up by upstream identity, the IdP and its subject both matching", () => {
		const user = { id: "u-1", username: "alice", email: "a@x.example", emailVerified: true };
		expect(ledger.answer(call("/upstream", { idp: "corp", subject: "up-1" }))).toEqual({
			json: user,
		});
		expect(ledger.answer(call("/upstream", { idp: "other", subject: "up-1" }))).toEqual({
			status: 404,
		});
		expect(ledger.answer(call("/upstream", { idp: "corp", subject: "u-1" }))).toEqual({
			status: 404,
		});
	});

	it("answers 404 to its calls without its credential, and nothing to a call not its own", () => {
		expect(ledger.answer(call("/verify", { email: "alice", password: "right" }, "other"))).toEqual({
			status: 404,
		});
		expect(ledger.answer(call("/elsewhere", {}))).toBeUndefined();
	});
});
