import { describe, expect, it } from "vitest";
import { parseDecisions, parseItems, parseLedger } from "../src/checklist.ts";
import { exceptionProblems } from "../src/exceptions.ts";

const read = parseItems(
	"rfc9999",
	[
		"# RFC 9999: Example",
		"## 4 X",
		"- **rfc9999-4-a** SHOULD: a",
		"  deviates: D-1",
		"- **rfc9999-4-b** MUST: b",
		"  noncompliant: https://example.org/issues/1",
		"- **rfc9999-4-c** MUST: c",
		"  out-of-scope: not offered",
		"- **rfc9999-4-d** MUST: d",
		"- **rfc9999-4-e** MUST: e",
		"  deviates: D-1",
		"- **rfc9999-4-f** SHOULD: f",
		"  deviates: D-99",
	].join("\n"),
);
const known = {
	items: new Map(read.items.map((i) => [i.id, i])),
	decisions: parseDecisions("- **D-1** 2026-10-26 (owner): keep it.").decisions,
};

describe("exceptionProblems", () => {
	it("takes an exception whose class is the mark of the item it names", () => {
		for (const [cls, item] of [
			["deviates", "rfc9999-4-a"],
			["noncompliant", "rfc9999-4-b"],
			["out-of-scope", "rfc9999-4-c"],
		] as const) {
			expect(exceptionProblems({ class: cls, item }, known)).toEqual([]);
		}
		expect(exceptionProblems({ class: "adaptation", adaptation: "pkce" }, known)).toEqual([]);
		expect(
			exceptionProblems({ class: "third-party", issue: "https://example.org/issues/2" }, known),
		).toEqual([]);
	});

	it("refuses an exception whose item is unknown, unmarked or marked otherwise", () => {
		expect(exceptionProblems({ class: "deviates", item: "rfc9999-4-z" }, known)).toEqual([
			"names rfc9999-4-z, which the checklist does not hold",
		]);
		expect(exceptionProblems({ class: "deviates", item: "rfc9999-4-d" }, known)).toEqual([
			"rfc9999-4-d is not marked deviates",
		]);
		expect(exceptionProblems({ class: "deviates", item: "rfc9999-4-b" }, known)).toEqual([
			"rfc9999-4-b is not marked deviates",
		]);
		expect(exceptionProblems({ class: "noncompliant" }, known)).toEqual(["names no item"]);
	});

	it("refuses an adaptation or a third party's exception without its name or issue, or with an item", () => {
		expect(exceptionProblems({ class: "adaptation" }, known)).toEqual(["names no adaptation"]);
		expect(exceptionProblems({ class: "third-party", issue: "see the forum" }, known)).toEqual([
			"names no issue URL at https",
		]);
		expect(
			exceptionProblems({ class: "adaptation", adaptation: "pkce", item: "rfc9999-4-d" }, known),
		).toEqual(["names an item, which an adaptation's exception reaches through its test"]);
	});

	it("refuses deviates on an item that is no SHOULD, or whose decision the decisions do not hold", () => {
		expect(exceptionProblems({ class: "deviates", item: "rfc9999-4-e" }, known)).toEqual([
			"rfc9999-4-e is a MUST, and deviates is for a SHOULD alone",
		]);
		expect(exceptionProblems({ class: "deviates", item: "rfc9999-4-f" }, known)).toEqual([
			"rfc9999-4-f names the decision D-99, which the decisions do not hold",
		]);
	});

	describe("an optional behaviour the provider does not give, or gives otherwise", () => {
		const ledger = parseLedger(
			"rfc9999",
			[
				"- source: https://example.org/rfc9999.txt",
				"- version: 1",
				`- sha256: ${"0".repeat(64)}`,
				"- 4 #1 MUST: rfc9999-4-d",
				"- 4 #2 SHOULD: rfc9999-4-a",
			].join("\n"),
		).ledger;
		const withLedgers = { ...known, ledgers: new Map([["rfc9999", ledger]]) };
		const optional = (more: Record<string, string> = {}) => ({
			class: "optional" as const,
			spec: "rfc9999",
			section: "4",
			...more,
		});

		it("is taken naming a spec whose ledger the checklist holds and a section of it, with or without a decision the decisions hold", () => {
			expect(exceptionProblems(optional(), withLedgers)).toEqual([]);
			expect(exceptionProblems(optional({ decision: "D-1" }), withLedgers)).toEqual([]);
			// A section of MAYs alone holds no ledger row, and is what this class is for.
			expect(exceptionProblems(optional({ section: "5" }), withLedgers)).toEqual([]);
		});

		it("is refused naming an item, no spec, a spec the ledgers do not hold, or a decision the decisions do not", () => {
			expect(exceptionProblems(optional({ item: "rfc9999-4-d" }), withLedgers)).toEqual([
				"names an item, which an optional exception reaches through its test",
			]);
			expect(exceptionProblems({ class: "optional", section: "4" }, withLedgers)).toEqual([
				"names no spec and section",
			]);
			expect(exceptionProblems(optional({ spec: "rfc0000" }), withLedgers)).toEqual([
				"names rfc0000, of which the checklist holds no ledger",
			]);
			expect(exceptionProblems(optional({ decision: "D-9" }), withLedgers)).toEqual([
				"names the decision D-9, which the decisions do not hold",
			]);
			expect(exceptionProblems(optional(), known)).toEqual([
				"cannot be checked without the ledgers",
			]);
		});

		it("is refused where its test names an item a MUST or SHOULD row of that section names", () => {
			expect(exceptionProblems(optional(), withLedgers, ["rfc9999-4-d"])).toEqual([
				"its test names rfc9999-4-d, which section 4's MUST names",
			]);
			expect(exceptionProblems(optional(), withLedgers, ["rfc9999-4-c"])).toEqual([]);
		});
	});
});
