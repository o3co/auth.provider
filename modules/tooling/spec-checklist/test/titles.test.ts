import { describe, expect, it } from "vitest";
import { titlesIn } from "../src/titles.ts";

const source = [
	'import { describe, it, test } from "vitest";',
	'describe("revocation [rfc7009-2-a]", () => {',
	'\tit("refuses a request without token [rfc7009-2.1-a] [rfc7009-5-a]", () => {});',
	'\tit.each([1, 2])("case %s [rfc7009-2-b]", () => {});',
	"\tit.runIf(true)(`a template [rfc7009-2-c]`, () => {});",
	'\ttest.skipIf(false).concurrent("chained [rfc7009-2-d]", () => {});',
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
				{ title: "a template [rfc7009-2-c]", ids: ["rfc7009-2-c"] },
				{ title: "chained [rfc7009-2-d]", ids: ["rfc7009-2-d"] },
			],
			stray: [],
		});
	});

	it("names an ID written anywhere but a title: a wrapper's title, a comment, a template with a substitution, a plain string", () => {
		const wrapped = [
			"const unless = (d: string) => it.runIf(d === '');",
			'unless("x")("wrapped [rfc7009-2-a]", () => {});',
			"// see rfc7636-4.4-a",
			// A template with a substitution, written in two parts.
			"it(`made $" + '{"up"} [rfc7009-2-b]`, () => {});',
			'const id = "oidc-core-3.1.2.1-a";',
		].join("\n");
		expect(titlesIn(wrapped, true)).toEqual({
			titles: [],
			stray: ["rfc7009-2-a", "rfc7636-4.4-a", "rfc7009-2-b", "oidc-core-3.1.2.1-a"],
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
