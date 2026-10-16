import { testRequest } from "@mod/http/testing";
import { describe, expect, it } from "vitest";
import { bodyOf } from "../body.ts";

/** A body read with the texts `sub`, `scope` and the number `min_ttl`, and what reading it comes to: `read`, or the refusal. */
const bodyCases: readonly {
	readonly name: string;
	readonly json?: Readonly<Record<string, unknown>>;
	readonly form?: Readonly<Record<string, readonly string[]>>;
	readonly said: string;
}[] = [
	{ name: "reads what it takes", json: { sub: "a", min_ttl: 5 }, said: "read" },
	{ name: "lets a client's credentials through", json: { sub: "a", client_id: "w" }, said: "read" },
	{ name: "refuses a name it does not take", json: { other: "x" }, said: "unexpected_parameter" },
	{
		name: "refuses a name it does not take, of any type",
		json: { other: { a: 1 } },
		said: "unexpected_parameter",
	},
	{ name: "refuses a text of another type", json: { sub: 5 }, said: "invalid_sub" },
	{ name: "refuses a name given twice", form: { sub: ["a", "b"] }, said: "duplicate_sub" },
	{ name: "reads digits as a number", form: { min_ttl: ["15"] }, said: "read" },
	{
		name: "refuses more than 15 digits",
		form: { min_ttl: ["1234567890123456"] },
		said: "invalid_min_ttl",
	},
	{ name: "refuses a fraction", json: { min_ttl: 1.5 }, said: "invalid_min_ttl" },
	{ name: "refuses a number below zero", json: { min_ttl: -1 }, said: "invalid_min_ttl" },
];

describe("reading a route's body", () => {
	for (const c of bodyCases) {
		it(c.name, () => {
			const form = c.form && new Map(Object.entries(c.form).map(([k, v]) => [k, [...v]]));
			const request = testRequest({
				method: "POST",
				...(c.json ? { json: c.json } : { fields: form ?? new Map() }),
			});
			const body = bodyOf(request, ["sub", "scope"], ["min_ttl"]);
			expect(body.kind === "read" ? "read" : body.description).toBe(c.said);
		});
	}
});
