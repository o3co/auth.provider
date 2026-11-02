import { describe, expect, it } from "vitest";
import { parseItems } from "../src/checklist.ts";
import { reportFiles, staticStatus, summaryTable } from "../src/report.ts";

const read = parseItems(
	"rfc9999",
	[
		"# RFC 9999: Example | One",
		"## 4 X",
		"- **rfc9999-4-a** MUST: tested | piped",
		"- **rfc9999-4-b** MUST: untested",
		"- **rfc9999-4-c** SHOULD: aside",
		"  deviates: D-1",
		"- **rfc9999-4-d** MUST: off",
		"  out-of-scope: not offered",
		"- **rfc9999-4-e** MUST: broken",
		"  noncompliant: https://example.org/issues/1",
		"  updates: rfc1111-3-a",
	].join("\n"),
);
const spec = { spec: "rfc9999", title: read.title, items: read.items, ledger: undefined };
const tests = new Map([
	[
		"rfc9999-4-a",
		[
			{
				pkg: "@mod/x",
				file: "test/x.test.ts",
				title: "answers [rfc9999-4-a]",
				path: ["answers [rfc9999-4-a]"],
				suite: false,
			},
		],
	],
]);

describe("staticStatus", () => {
	it("is the mark where there is one, else mapped with a test and hole without", () => {
		expect(read.items.map((i) => staticStatus(i, tests))).toEqual([
			"mapped",
			"hole",
			"deviates",
			"out-of-scope",
			"noncompliant",
		]);
	});
});

describe("summaryTable", () => {
	it("counts each spec's items by class and status, and totals them", () => {
		expect(summaryTable([spec], tests)).toContain(
			"| [RFC 9999: Example \\| One](rfc9999.md) | 5 | 3 | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 1 |",
		);
		expect(summaryTable([spec, spec], tests)).toContain(
			"| Total | 10 | 6 | 2 | 2 | 2 | 2 | 0 | 0 | 2 | 2 |",
		);
		expect(summaryTable([spec], tests)).toContain("| as | 5 | 3 | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 1 |");
		expect(summaryTable([spec], tests)).toContain("| rp | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |");
	});
});

describe("reportFiles", () => {
	it("titles the README a checklist, claiming no compliance", () => {
		const readme = reportFiles([spec], tests, new Map()).get("README.md") ?? "";
		expect(readme.split("\n")[0]).toBe("# Specification checklist");
	});

	it("writes a page per spec and a README naming none, escaping what would break a table", () => {
		const files = reportFiles([spec], tests, new Map([["rfc1111-3-a", ["rfc9999-4-e"]]]));
		expect([...files.keys()]).toEqual(["README.md", "rfc9999.md"]);
		expect(files.get("README.md")).not.toContain("RFC 9999");
		const table = files.get("rfc9999.md") ?? "";
		expect(table).toContain(
			"| rfc9999-4-a | MUST | as | mapped | tested \\| piped | @mod/x › test/x.test.ts › answers [rfc9999-4-a] |",
		);
		expect(table).toContain(
			"| rfc9999-4-e | MUST | as | noncompliant | broken |  | https://example.org/issues/1; updates rfc1111-3-a |",
		);
	});
});

describe("notes", () => {
	it("points an item's note cell at the note, written once in the README's notes", () => {
		const noted = parseItems(
			"rfc9999",
			"# RFC 9999: Example\n## 4 X\n- **rfc9999-4-a** MUST: a\n  note: N-https\n",
		);
		const notes = new Map([["N-https", { id: "N-https", text: "Production holds to https." }]]);
		const files = reportFiles(
			[{ spec: "rfc9999", title: noted.title, items: noted.items, ledger: undefined }],
			new Map(),
			new Map(),
			notes,
		);
		expect(files.get("rfc9999.md")).toContain("| [N-https](README.md#n-https) |");
		const readme = files.get("README.md") ?? "";
		expect(readme).toContain('- <a id="n-https"></a>**N-https**: Production holds to https.');
		expect(readme.split("Production holds to https.").length).toBe(2);
	});
});
