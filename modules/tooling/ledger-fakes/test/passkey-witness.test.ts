import { describe, expect, it } from "vitest";
import { type LedgerCall, passkeyWitnessLedger } from "../src/contract.ts";

describe("a fake ledger keeping the passkey witness", () => {
	const ledger = passkeyWitnessLedger();
	const call = (path: string, body: unknown, credential = ledger.credential): LedgerCall => ({
		method: "POST",
		path: `/passkey-witness/${path}`,
		headers: { authorization: `Bearer ${credential}` },
		body: JSON.stringify(body),
	});

	it("serves its three calls at one origin, under a credential of its own", () => {
		expect(ledger.urls("http://127.0.0.1:1")).toEqual({
			read: "http://127.0.0.1:1/passkey-witness/read",
			enroll: "http://127.0.0.1:1/passkey-witness/enroll",
			withdraw: "http://127.0.0.1:1/passkey-witness/withdraw",
		});
		expect(ledger.credential).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});

	it("says whether a subject is enrolled with its mark's token, takes the first mark only, and withdraws it only by its token", () => {
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
		expect(ledger.answer(call("withdraw", { subject: "u-1", token: "b" }))).toEqual({
			status: 204,
		});
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({
			json: { enrolled: true, token: "a" },
		});
		expect(ledger.answer(call("withdraw", { subject: "u-1", token: "a" }))).toEqual({
			status: 204,
		});
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({ json: { enrolled: false } });
		expect(ledger.answer(call("enroll", { subject: "u-1", token: "c" }))).toEqual({
			json: { owner: true },
		});
		expect(ledger.answer(call("read", { subject: "u-1" }))).toEqual({
			json: { enrolled: true, token: "c" },
		});
	});

	it("answers 404 to its calls without its credential, and nothing to a call not its own", () => {
		expect(ledger.answer(call("read", { subject: "u-1" }, "other"))).toEqual({ status: 404 });
		expect(ledger.answer({ ...call("read", {}), path: "/verify" })).toBeUndefined();
		// The passkey witness is only withdrawn by its token: no clear is its call.
		expect(ledger.answer(call("clear", { subject: "u-1" }))).toBeUndefined();
	});
});
