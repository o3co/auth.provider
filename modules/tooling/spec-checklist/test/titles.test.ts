import { describe, expect, it } from "vitest";
import { titlesIn } from "../src/titles.ts";

const source = [
	'import { describe, it, test } from "vitest";',
	'describe("revocation [rfc7009-2-a]", () => {',
	'\tit("refuses a request without token [rfc7009-2.1-a] [rfc7009-5-a]", () => {});',
	'\tit.each([1, 2])("case %s [rfc7009-2-b]", () => {});',
	'\tit.runIf(true)("conditional [rfc7009-2-c]", () => {});',
	'\ttest.skipIf(false).concurrent("chained [rfc7009-2-d]", () => {});',
	'\tit.only("focused [rfc7636-4.4-a]", () => {});',
	'\tit("no ID here", () => {});',
	"});",
].join("\n");

describe("titlesIn", () => {
	it("reads the IDs in the titles of it, test and describe, through their modifiers", () => {
		expect(titlesIn(source, true)).toEqual({
			titles: [
				{ title: "revocation [rfc7009-2-a]", ids: ["rfc7009-2-a"] },
				{
					title: "refuses a request without token [rfc7009-2.1-a] [rfc7009-5-a]",
					ids: ["rfc7009-2.1-a", "rfc7009-5-a"],
				},
				{ title: "case %s [rfc7009-2-b]", ids: ["rfc7009-2-b"] },
				{ title: "conditional [rfc7009-2-c]", ids: ["rfc7009-2-c"] },
				{ title: "chained [rfc7009-2-d]", ids: ["rfc7009-2-d"] },
				{ title: "focused [rfc7636-4.4-a]", ids: ["rfc7636-4.4-a"] },
			],
			stray: [],
		});
	});

	it("takes no title from a modifier's own arguments: a condition or a table is no title", () => {
		const modifiers = [
			'it.runIf("[rfc7009-2-a]")("unrelated [rfc7009-2-b]", () => {});',
			'it.each(["[rfc7009-2-c]"])("case %s", () => {});',
			'test.skipIf("[rfc7009-2-d]").concurrent("chained", () => {});',
		].join("\n");
		expect(titlesIn(modifiers, true)).toEqual({
			titles: [{ title: "unrelated [rfc7009-2-b]", ids: ["rfc7009-2-b"] }],
			stray: ["rfc7009-2-a", "rfc7009-2-c", "rfc7009-2-d"],
		});
	});

	it("reads the title a tagged template's table leads to, and takes no title from the table", () => {
		const tagged = [
			"it.each`",
			"\ta | b",
			"\t$" + "{1} | $" + "{2}",
			'`("adds $a and $b [rfc7009-2-a]", () => {});',
			"describe.for`x $" + '{1}`("grouped [rfc7009-2-b]", () => {});',
			"test.concurrent.each`n $" + '{1} [rfc7009-2-c]`("case [rfc7009-2-d]", () => {});',
		].join("\n");
		expect(titlesIn(tagged, true)).toEqual({
			titles: [
				{ title: "adds $a and $b [rfc7009-2-a]", ids: ["rfc7009-2-a"] },
				{ title: "grouped [rfc7009-2-b]", ids: ["rfc7009-2-b"] },
				{ title: "case [rfc7009-2-d]", ids: ["rfc7009-2-d"] },
			],
			stray: ["rfc7009-2-c"],
		});
	});

	it("names an ID written anywhere but a title: a wrapper's title, a comment, any template, a plain string", () => {
		const wrapped = [
			"const unless = (d: string) => it.runIf(d === '');",
			'unless("x")("wrapped [rfc7009-2-a]", () => {});',
			"// see rfc7636-4.4-a",
			"it(`a template [rfc7009-2-c]`, () => {});",
			// A template with a substitution, written in two parts.
			"it(`made $" + '{"up"} [rfc7009-2-b]`, () => {});',
			'const id = "oidc-core-3.1.2.1-a";',
		].join("\n");
		expect(titlesIn(wrapped, true)).toEqual({
			titles: [],
			stray: ["rfc7009-2-a", "rfc7636-4.4-a", "rfc7009-2-c", "rfc7009-2-b", "oidc-core-3.1.2.1-a"],
		});
	});

	it("reads a string as it decodes, so an escape hides no ID", () => {
		const escaped = [
			'it("escaped [\\u0072fc7009-2-a]", () => {});',
			'const hidden = "\\u0072fc9999-2-a";',
		].join("\n");
		expect(titlesIn(escaped, true)).toEqual({
			titles: [{ title: "escaped [rfc7009-2-a]", ids: ["rfc7009-2-a"] }],
			stray: ["rfc9999-2-a"],
		});
	});

	it("names an ID written like an item's but malformed, in a title or not", () => {
		const malformed = [
			'it("upper [rfc7009-2-A]", () => {});',
			'it("long [rfc7009-2-aaa]", () => {});',
			'const tail = "rfc7009-2-a-b";',
		].join("\n");
		expect(titlesIn(malformed, true)).toEqual({
			titles: [
				{ title: "upper [rfc7009-2-A]", ids: [] },
				{ title: "long [rfc7009-2-aaa]", ids: [] },
			],
			stray: ["rfc7009-2-A", "rfc7009-2-aaa", "rfc7009-2-a-b"],
		});
	});

	it("names an ID in a title that is not in brackets, and every ID in a file that holds no tests", () => {
		expect(titlesIn('it("covers rfc7009-2-a", () => {});', true)).toEqual({
			titles: [{ title: "covers rfc7009-2-a", ids: [] }],
			stray: ["rfc7009-2-a"],
		});
		expect(titlesIn('it("x [rfc7009-2-a]", () => {});', false)).toEqual({
			titles: [],
			stray: ["rfc7009-2-a"],
		});
	});
});
