import { describe, expect, it } from "vitest";
import { parseItems } from "../src/checklist.ts";
import { reportFiles, staticStatus } from "../src/report.ts";

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
	["rfc9999-4-a", [{ pkg: "@mod/x", file: "test/x.test.ts", title: "answers [rfc9999-4-a]" }]],
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

describe("reportFiles", () => {
	it("writes a summary and a table per spec, escaping what would break a table", () => {
		const files = reportFiles([spec], tests, new Map([["rfc1111-3-a", ["rfc9999-4-e"]]]));
		expect([...files.keys()]).toEqual(["README.md", "rfc9999.md"]);
		expect(files.get("README.md")).toContain(
			"| [RFC 9999: Example \\| One](rfc9999.md) | 5 | 3 | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 1 |",
		);
		expect(files.get("README.md")).toContain("| as | 5 | 3 | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 1 |");
		expect(files.get("README.md")).toContain("| rp | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |");
		const table = files.get("rfc9999.md") ?? "";
		expect(table).toContain(
			"| rfc9999-4-a | MUST | as | mapped | tested \\| piped | @mod/x › test/x.test.ts › answers [rfc9999-4-a] |",
		);
		expect(table).toContain(
			"| rfc9999-4-e | MUST | as | noncompliant | broken |  | https://example.org/issues/1; updates rfc1111-3-a |",
		);
	});
});
