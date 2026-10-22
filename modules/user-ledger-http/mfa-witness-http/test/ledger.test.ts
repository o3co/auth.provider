import { describe, expect, it } from "vitest";
import { type LedgerCall, witnessLedger } from "../src/testing.ts";

describe("a fake ledger keeping mfa's witness", () => {
	const ledger = witnessLedger();
	const section = ledger.section("http://127.0.0.1:1")["mfa-witness-http"];
	const call = (path: string, body: unknown, credential = section.credential): LedgerCall => ({
		method: "POST",
		path: `/mfa-witness/${path}`,
		headers: { authorization: `Bearer ${credential}` },
		body: JSON.stringify(body),
	});

	it("points mfa-witness-http at its four calls at one origin, under a credential of its own", () => {
		expect(section).toEqual({
			"read-url": "http://127.0.0.1:1/mfa-witness/read",
			"enroll-url": "http://127.0.0.1:1/mfa-witness/enroll",
			"clear-url": "http://127.0.0.1:1/mfa-witness/clear",
			"withdraw-url": "http://127.0.0.1:1/mfa-witness/withdraw",
			credential: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
		});
	});

	it("withdraws a mark only where it is the token's, answering 204 either way", () => {
		ledger.answer(call("enroll", { subject: "u-2", token: "a" }));
		expect(ledger.answer(call("withdraw", { subject: "u-2", token: "b" }))).toEqual({
			status: 204,
		});
		expect(ledger.answer(call("read", { subject: "u-2" }))).toEqual({
			json: { enrolled: true, token: "a" },
		});
		expect(ledger.answer(call("withdraw", { subject: "u-2", token: "a" }))).toEqual({
			status: 204,
		});
		expect(ledger.answer(call("read", { subject: "u-2" }))).toEqual({ json: { enrolled: false } });
	});

	it("plays a ledger with no withdraw route where made so, leaving the URL out", () => {
		const older = witnessLedger({ withdraw: false });
		const pointed = older.section("http://127.0.0.1:1")["mfa-witness-http"];
		expect("withdraw-url" in pointed).toBe(false);
		const asked: LedgerCall = {
			method: "POST",
			path: "/mfa-witness/withdraw",
			headers: { authorization: `Bearer ${pointed.credential}` },
			body: JSON.stringify({ subject: "u-1", token: "a" }),
		};
		expect(older.answer(asked)).toBeUndefined();
	});

	it("says whether a subject is enrolled and by which token, takes the first mark only, and clears it", () => {
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({ json: { enrolled: false } });
		expect(ledger.answer(call("enroll", { subject: "u-1", token: "a" }))).toEqual({
			json: { owner: true },
		});
		expect(ledger.answer(call("enroll", { subject: "u-1", token: "b" }))).toEqual({
			json: { owner: false },
		});
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({
			json: { enrolled: true, token: "a" },
		});
		expect(ledger.answer(call("clear", { subject: "u-1" }))).toEqual({ status: 204 });
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({ json: { enrolled: false } });
	});

	it("answers 404 to its calls without its credential, and nothing to a call not its own", () => {
		expect(ledger.answer(call("read", { subject: "u-1" }, "other"))).toEqual({ status: 404 });
		expect(ledger.answer({ ...call("read", {}), path: "/verify" })).toBeUndefined();
	});
});
