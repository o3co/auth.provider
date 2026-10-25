import { describe, expect, it } from "vitest";
import { parseItems } from "../src/checklist.ts";
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
	].join("\n"),
);
const items = new Map(read.items.map((i) => [i.id, i]));

describe("exceptionProblems", () => {
	it("takes an exception whose class is the mark of the item it names", () => {
		for (const [cls, item] of [
			["deviates", "rfc9999-4-a"],
			["noncompliant", "rfc9999-4-b"],
			["out-of-scope", "rfc9999-4-c"],
		] as const) {
			expect(exceptionProblems({ class: cls, item }, items)).toEqual([]);
		}
		expect(exceptionProblems({ class: "adaptation", adaptation: "pkce" }, items)).toEqual([]);
		expect(
			exceptionProblems({ class: "third-party", issue: "https://example.org/issues/2" }, items),
		).toEqual([]);
	});

	it("refuses an exception whose item is unknown, unmarked or marked otherwise", () => {
		expect(exceptionProblems({ class: "deviates", item: "rfc9999-4-z" }, items)).toEqual([
			"names rfc9999-4-z, which the checklist does not hold",
		]);
		expect(exceptionProblems({ class: "deviates", item: "rfc9999-4-d" }, items)).toEqual([
			"rfc9999-4-d is not marked deviates",
		]);
		expect(exceptionProblems({ class: "deviates", item: "rfc9999-4-b" }, items)).toEqual([
			"rfc9999-4-b is not marked deviates",
		]);
		expect(exceptionProblems({ class: "noncompliant" }, items)).toEqual(["names no item"]);
	});

	it("refuses an adaptation or a third party's exception without its name or issue, or with an item", () => {
		expect(exceptionProblems({ class: "adaptation" }, items)).toEqual(["names no adaptation"]);
		expect(exceptionProblems({ class: "third-party", issue: "see the forum" }, items)).toEqual([
			"names no issue URL at https",
		]);
		expect(
			exceptionProblems({ class: "adaptation", adaptation: "pkce", item: "rfc9999-4-d" }, items),
		).toEqual(["names an item, which an adaptation's exception reaches through its test"]);
	});
});
