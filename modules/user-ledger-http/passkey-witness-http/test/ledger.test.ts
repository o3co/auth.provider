import { describe, expect, it } from "vitest";
import { type LedgerCall, witnessLedger } from "../src/testing.ts";

describe("a fake ledger keeping the passkey witness", () => {
	const ledger = witnessLedger();
	const section = ledger.section("http://127.0.0.1:1")["passkey-witness-http"];
	const call = (path: string, body: unknown, credential = section.credential): LedgerCall => ({
		method: "POST",
		path: `/passkey-witness/${path}`,
		headers: { authorization: `Bearer ${credential}` },
		body: JSON.stringify(body),
	});

	it("points passkey-witness-http at its four calls at one origin, under a credential of its own", () => {
		expect(section).toEqual({
			"read-url": "http://127.0.0.1:1/passkey-witness/read",
			"enroll-url": "http://127.0.0.1:1/passkey-witness/enroll",
			"withdraw-url": "http://127.0.0.1:1/passkey-witness/withdraw",
			"clear-url": "http://127.0.0.1:1/passkey-witness/clear",
			credential: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
		});
	});

	it("says whether a subject is enrolled, takes the first mark only, withdraws it only by its token, and clears it", () => {
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({ json: { enrolled: false } });
		expect(ledger.answer(call("enroll", { subject: "u-1", token: "a" }))).toEqual({
			json: { owner: true },
		});
		expect(ledger.answer(call("enroll", { subject: "u-1", token: "b" }))).toEqual({
			json: { owner: false },
		});
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({ json: { enrolled: true } });
		expect(ledger.answer(call("withdraw", { subject: "u-1", token: "b" }))).toEqual({
			status: 204,
		});
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({ json: { enrolled: true } });
		expect(ledger.answer(call("withdraw", { subject: "u-1", token: "a" }))).toEqual({
			status: 204,
		});
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({ json: { enrolled: false } });
		expect(ledger.answer(call("enroll", { subject: "u-1", token: "c" }))).toEqual({
			json: { owner: true },
		});
		expect(ledger.answer(call("clear", { subject: "u-1" }))).toEqual({ status: 204 });
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({ json: { enrolled: false } });
	});

	it("answers 404 to its calls without its credential, and nothing to a call not its own", () => {
		expect(ledger.answer(call("read", { subject: "u-1" }, "other"))).toEqual({ status: 404 });
		expect(ledger.answer({ ...call("read", {}), path: "/verify" })).toBeUndefined();
	});
});
