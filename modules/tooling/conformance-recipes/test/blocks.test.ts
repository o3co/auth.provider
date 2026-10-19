import { describe, expect, it } from "vitest";
import { withBlocks } from "../src/blocks.ts";

const doc = [
	"# A recipe",
	"",
	"Written by hand.",
	"<!-- generated:command -->",
	"old",
	"<!-- end generated -->",
	"More by hand.",
	"<!-- generated:flow -->",
	"<!-- end generated -->",
	"",
].join("\n");

describe("generated blocks", () => {
	it("puts each block's text between its marks and touches nothing outside them", () => {
		const out = withBlocks(doc, { command: "new\n", flow: "a\nb" });
		expect(out).toBe(
			[
				"# A recipe",
				"",
				"Written by hand.",
				"<!-- generated:command -->",
				"new",
				"<!-- end generated -->",
				"More by hand.",
				"<!-- generated:flow -->",
				"a",
				"b",
				"<!-- end generated -->",
				"",
			].join("\n"),
		);
		expect(withBlocks(out, { command: "new\n", flow: "a\nb" })).toBe(out);
	});

	it("refuses a block with no marks, marks with no block, a name marked twice and an unclosed mark", () => {
		expect(() => withBlocks(doc, { command: "x", flow: "y", other: "z" })).toThrow(/other/);
		expect(() => withBlocks(doc, { command: "x" })).toThrow(/flow/);
		const twice = `${doc}<!-- generated:command -->\n<!-- end generated -->\n`;
		expect(() => withBlocks(twice, { command: "x", flow: "y" })).toThrow(/twice/);
		expect(() => withBlocks("<!-- generated:open -->\nno end\n", { open: "x" })).toThrow(/closing/);
	});
});
