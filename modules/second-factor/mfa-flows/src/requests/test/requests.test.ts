import { testRequest } from "@mod/http/testing";
import { describe, expect, it } from "vitest";
import type { Transaction } from "../../transactions/records.ts";
import { field, postedTransaction, proofOf, revokedSince } from "../requests.ts";

const posted = (
	body: Readonly<Record<string, unknown>> | undefined,
	header?: string,
	query?: Readonly<Record<string, string>>,
) =>
	testRequest({
		method: "POST",
		...(body ? { json: body } : {}),
		...(header ? { headers: new Map([["mfa-transaction", header]]) } : {}),
		...(query ? { query: new Map(Object.entries(query).map(([k, v]) => [k, [v]])) } : {}),
	});

describe("a value a POST names", () => {
	it("is read from its body alone, never its query", () => {
		expect(field(posted({ kind: "totp" }), "kind")).toBe("totp");
		expect(field(posted({}, undefined, { kind: "totp" }), "kind")).toBeUndefined();
	});
});

describe("the transaction a POST names", () => {
	it("is its body's or its header's, the same where both name it", () => {
		expect(postedTransaction(posted({ transaction_id: "t1" }))).toBe("t1");
		expect(postedTransaction(posted(undefined, "t1"))).toBe("t1");
		expect(postedTransaction(posted({ transaction_id: "t1" }, "t1"))).toBe("t1");
	});

	it("is none where neither names one, and refused where the two differ", () => {
		expect(postedTransaction(posted({}))).toBeUndefined();
		expect(postedTransaction(posted({ transaction_id: "t1" }, "t2"))).toBe(false);
	});

	it("is never read from the query", () => {
		expect(postedTransaction(posted({}, undefined, { transaction_id: "t1" }))).toBeUndefined();
	});
});

describe("the proof a POST sends", () => {
	it("is a string as it is, and an object as its JSON text", () => {
		expect(proofOf(posted({ proof: "123456" }))).toBe("123456");
		expect(proofOf(posted({ proof: { id: "c", type: "public-key" } }))).toBe(
			'{"id":"c","type":"public-key"}',
		);
	});

	it("is none where it is an array, a number or missing", () => {
		expect(proofOf(posted({ proof: ["a"] }))).toBeUndefined();
		expect(proofOf(posted({ proof: 7 }))).toBeUndefined();
		expect(proofOf(posted({}))).toBeUndefined();
	});
});

describe("whether a transaction's subject was revoked since", () => {
	const t = { subject: "ola", startedAt: 1_000 } as Transaction;

	it("asks for the subject, from when the transaction started", async () => {
		const asked: unknown[] = [];
		const check = async (subject: string, since: number) => {
			asked.push([subject, since]);
			return "revoked" as const;
		};
		expect(await revokedSince({ check }, t)).toBe(true);
		expect(asked).toEqual([["ola", 1_000]]);
	});

	it("is not where the subject stands", async () => {
		expect(await revokedSince({ check: async () => "valid" as const }, t)).toBe(false);
	});
});
