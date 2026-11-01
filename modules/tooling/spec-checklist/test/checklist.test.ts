import { describe, expect, it } from "vitest";
import {
	checklistFindings,
	parseDecisions,
	parseItems,
	parseLedger,
	parseNotes,
} from "../src/checklist.ts";

const items = (body: string) => `# RFC 9999: Example\n\n${body}`;
const ledger = (rows: string) =>
	`# RFC 9999 ledger\n\n- source: https://example.org/rfc9999.txt\n- version: RFC 9999\n- sha256: ${"a".repeat(64)}\n\n${rows}`;

/** The findings of one spec's items and ledger, with the decisions given. */
function findings(
	itemText: string,
	ledgerText: string,
	decisions = "# Decisions\n",
	notes = "# Notes\n",
) {
	const parsed = parseItems("rfc9999", itemText);
	const read = parseLedger("rfc9999", ledgerText);
	return checklistFindings({
		specs: [{ spec: "rfc9999", title: parsed.title, items: parsed.items, ledger: read.ledger }],
		decisions: parseDecisions(decisions).decisions,
		notes: parseNotes(notes).notes,
		parsing: [...parsed.findings, ...read.findings],
	}).map((f) => f.detail);
}

describe("items", () => {
	it("reads an item with its section, strength, text and mark", () => {
		const read = parseItems(
			"rfc9999",
			items(
				"## 4.1 Request\n\n- **rfc9999-4.1-a** MUST NOT: never this.\n  out-of-scope: not offered.\n",
			),
		);
		expect(read.findings).toEqual([]);
		expect(read.title).toBe("RFC 9999: Example");
		expect(read.items).toEqual([
			{
				id: "rfc9999-4.1-a",
				spec: "rfc9999",
				section: "4.1",
				strength: "MUST NOT",
				text: "never this.",
				mark: { kind: "out-of-scope", reason: "not offered." },
				updates: [],
				role: "as",
			},
		]);
	});

	it("takes an item's role from its spec, from the file's head, or from its own role line", () => {
		const oidc = parseItems(
			"oidc-core",
			"# Core\n\n## 2 X\n\n- **oidc-core-2-a** MUST: a\n- **oidc-core-2-b** MUST: b\n  role: rp\n",
		);
		expect(oidc.items.map((i) => i.role)).toEqual(["op", "rp"]);
		const headed = parseItems(
			"rfc9999",
			items("- role: client\n\n## 4 X\n\n- **rfc9999-4-a** MUST: a\n"),
		);
		expect(headed.items.map((i) => i.role)).toEqual(["client"]);
		const wrong = parseItems(
			"rfc9999",
			items(
				"- role: user\n\n## 4 X\n\n- **rfc9999-4-a** MUST: a\n  role: rs\n  role: rp\n- **rfc9999-4-b** MUST: b\n  role: browser\n",
			),
		);
		expect(wrong.findings.map((f) => f.detail)).toEqual([
			"the file's role user is none of as, op, rs, rp, client",
			"rfc9999-4-a: has more than one role line",
			"rfc9999-4-b: its role browser is none of as, op, rs, rp, client",
		]);
	});

	it("refuses an item's second role line even after a first one it refused, keeping the role it took", () => {
		const twice = parseItems(
			"rfc9999",
			items("## 4 X\n\n- **rfc9999-4-a** MUST: a\n  role: browser\n  role: rp\n"),
		);
		expect(twice.findings.map((f) => f.detail)).toEqual([
			"rfc9999-4-a: its role browser is none of as, op, rs, rp, client",
			"rfc9999-4-a: has more than one role line",
		]);
		expect(twice.items.map((i) => i.role)).toEqual(["as"]);
	});

	it("refuses a second role line at the file's head, keeping the first for the items", () => {
		const twice = parseItems(
			"rfc9999",
			items("- role: as\n- role: rp\n\n## 4 X\n\n- **rfc9999-4-a** MUST: a\n"),
		);
		expect(twice.findings.map((f) => f.detail)).toEqual(["the file has more than one role line"]);
		expect(twice.items.map((i) => i.role)).toEqual(["as"]);
	});

	it("refuses a line that is no item, heading, mark or blank", () => {
		const read = parseItems("rfc9999", items("## 4 X\n\nsome prose\n- **rfc9999-4-a** MAY: x\n"));
		expect(read.findings.map((f) => f.detail)).toEqual([
			"not an item, a heading, a mark or a blank line: some prose",
			"not an item, a heading, a mark or a blank line: - **rfc9999-4-a** MAY: x",
		]);
	});

	it("refuses an ID of another spec, a malformed one, and one outside its heading's section", () => {
		const read = parseItems(
			"rfc9999",
			items(
				"## 4 X\n\n- **rfc1234-4-a** MUST: a\n- **rfc9999-4-A** MUST: b\n- **rfc9999-5-a** MUST: c\n",
			),
		);
		expect(read.findings.map((f) => f.detail)).toEqual([
			"rfc1234-4-a: names another spec than its file",
			"rfc9999-4-A: not an item ID",
			"rfc9999-5-a: is not of section 4, under which it is written",
		]);
	});

	it("refuses a second updates line, and a mark after a heading, which no item of its section precedes", () => {
		const read = parseItems(
			"rfc9999",
			items(
				"## 4 X\n\n- **rfc9999-4-a** MUST: a\n  updates: rfc1111-3-a\n  updates: rfc1111-3-b\n\n## 5 Y\n\n  out-of-scope: x\n",
			),
		);
		expect(read.findings.map((f) => f.detail)).toEqual([
			"rfc9999-4-a: has more than one updates line",
			"a mark with no item before it: out-of-scope: x",
		]);
		expect(read.items.map((i) => [i.id, i.updates, i.mark])).toEqual([
			["rfc9999-4-a", ["rfc1111-3-a"], undefined],
		]);
	});

	it("refuses an item before any section heading, and a mark with no item before it", () => {
		const read = parseItems(
			"rfc9999",
			items("  updates: rfc1234-1-a\n- **rfc9999-4-a** MUST: a\n"),
		);
		expect(read.findings.map((f) => f.detail)).toEqual([
			"a mark with no item before it: updates: rfc1234-1-a",
			"rfc9999-4-a: is written under no section heading",
		]);
	});
});

describe("marks", () => {
	const decisions = "# Decisions\n\n- **D-1** 2026-10-26 (owner): keep it.\n";

	it("takes deviates on a SHOULD with a known decision, noncompliant on a MUST", () => {
		const text = items(
			"## 4 X\n\n- **rfc9999-4-a** SHOULD: a\n  deviates: D-1\n- **rfc9999-4-b** MUST: b\n  noncompliant: https://example.org/issues/1\n",
		);
		expect(
			findings(text, ledger("- 4 #1 SHOULD: rfc9999-4-a\n- 4 #2 MUST: rfc9999-4-b\n"), decisions),
		).toEqual([]);
	});

	it("refuses deviates on a MUST, noncompliant on a SHOULD, an unknown decision, and two marks", () => {
		const text = items(
			"## 4 X\n\n- **rfc9999-4-a** MUST: a\n  deviates: D-1\n- **rfc9999-4-b** SHOULD: b\n  noncompliant: https://example.org/issues/1\n- **rfc9999-4-c** SHOULD: c\n  deviates: D-9\n- **rfc9999-4-d** SHOULD: d\n  deviates: D-1\n  out-of-scope: no\n",
		);
		const rows = ledger(
			"- 4 #1 MUST: rfc9999-4-a\n- 4 #2 SHOULD: rfc9999-4-b\n- 4 #3 SHOULD: rfc9999-4-c\n- 4 #4 SHOULD: rfc9999-4-d\n",
		);
		expect(findings(text, rows, decisions)).toEqual([
			"rfc9999-4-d: has more than one of out-of-scope, deviates and noncompliant",
			"rfc9999-4-a: deviates is for a SHOULD alone; a MUST not met is noncompliant",
			"rfc9999-4-b: noncompliant is for a MUST alone",
			"rfc9999-4-c: names the decision D-9, which the decisions do not hold",
		]);
	});

	it("takes updates of another spec's item no stronger than it, and refuses the rest", () => {
		const other = parseItems(
			"rfc1111",
			"# RFC 1111: Old\n\n## 3 Y\n\n- **rfc1111-3-a** SHOULD: old\n- **rfc1111-3-b** MUST: old\n",
		);
		const mine = parseItems(
			"rfc9999",
			items(
				"## 4 X\n\n- **rfc9999-4-a** MUST: a\n  updates: rfc1111-3-a\n- **rfc9999-4-b** SHOULD: b\n  updates: rfc1111-3-b, rfc1111-3-z, rfc9999-4-a\n",
			),
		);
		const result = checklistFindings({
			specs: [
				{ spec: "rfc1111", title: other.title, items: other.items, ledger: undefined },
				{ spec: "rfc9999", title: mine.title, items: mine.items, ledger: undefined },
			],
			decisions: new Map(),
			parsing: [],
		}).map((f) => f.detail);
		expect(result).toEqual([
			"rfc1111: has no ledger",
			"rfc9999: has no ledger",
			"rfc9999-4-b: updates rfc1111-3-b, a MUST, and is weaker than it",
			"rfc9999-4-b: updates rfc1111-3-z, which the checklist does not hold",
			"rfc9999-4-b: updates rfc9999-4-a, an item of its own spec",
		]);
	});
});

describe("ledger", () => {
	it("reads a ledger's head and rows", () => {
		const read = parseLedger(
			"rfc9999",
			ledger(
				"- front #1 MUST: excluded definition\n- 4 #1 SHALL NOT: rfc9999-4-a, rfc9999-4-b\n- A.1 #1 NOT RECOMMENDED: excluded other: advice\n",
			),
		);
		expect(read.findings).toEqual([]);
		expect(read.ledger).toEqual({
			source: "https://example.org/rfc9999.txt",
			version: "RFC 9999",
			sha256: "a".repeat(64),
			rows: [
				{
					section: "front",
					ordinal: 1,
					keyword: "MUST",
					to: { kind: "excluded", category: "definition" },
				},
				{
					section: "4",
					ordinal: 1,
					keyword: "SHALL NOT",
					to: { kind: "items", ids: ["rfc9999-4-a", "rfc9999-4-b"] },
				},
				{
					section: "A.1",
					ordinal: 1,
					keyword: "NOT RECOMMENDED",
					to: { kind: "excluded", category: "other", detail: "advice" },
				},
			],
		});
	});

	it("refuses a head without its source, version or digest, and an unknown exclusion", () => {
		const read = parseLedger(
			"rfc9999",
			"# RFC 9999 ledger\n\n- source: https://example.org/x.txt\n\n- 4 #1 MUST: excluded because\n- 4 #2 MUST: excluded other\n- 4 #3 MUST: excluded restates\n- 4 #4 MUST: excluded other-role\n",
		);
		expect(read.findings.map((f) => f.detail)).toEqual([
			"4 #1: excluded as because, which is no exclusion",
			"4 #2: other needs its reason",
			"4 #3: restates needs its reason",
			"4 #4: other-role needs its reason",
			"has no version",
			"has no sha256 of 64 hex digits",
		]);
	});

	it("holds a row that restates another spec's item to that item's strength", () => {
		const other = parseItems(
			"rfc1111",
			"# RFC 1111: Old\n\n## 3 Y\n\n- **rfc1111-3-a** SHOULD: old\n  deviates: D-1\n",
		);
		const mine = parseItems("rfc9999", items("## 4 X\n\n- **rfc9999-4-a** MUST: a\n"));
		const rows = parseLedger(
			"rfc9999",
			ledger(
				"- 4 #1 MUST: rfc9999-4-a\n- 4 #2 MUST: excluded restates rfc1111-3-a\n- 4 #3 SHOULD: excluded restates rfc1111-3-a\n",
			),
		);
		const result = checklistFindings({
			specs: [
				{ spec: "rfc1111", title: other.title, items: other.items, ledger: undefined },
				{ spec: "rfc9999", title: mine.title, items: mine.items, ledger: rows.ledger },
			],
			decisions: parseDecisions("- **D-1** 2026-10-26 (owner): keep it.").decisions,
			parsing: [],
		}).map((f) => f.detail);
		expect(result).toEqual(["rfc1111: has no ledger", "4 #2: MUST restates rfc1111-3-a, a SHOULD"]);
	});

	it("holds every item to a row, rows to items of its spec, and a row's keyword to its item's strength", () => {
		const text = items(
			"## 4 X\n\n- **rfc9999-4-a** MUST: a\n- **rfc9999-4-b** SHOULD: b\n- **rfc9999-4-c** MUST: c\n",
		);
		const rows = ledger(
			"- 4 #1 MUST: rfc9999-4-a\n- 4 #2 SHOULD: rfc9999-4-a\n- 4 #3 RECOMMENDED: rfc9999-4-b, rfc9999-4-z\n- 4 #5 MUST: excluded restates rfc9999-4-y\n",
		);
		expect(findings(text, rows)).toEqual([
			"4 #2: SHOULD names rfc9999-4-a, a MUST",
			"4 #3: names rfc9999-4-z, which the spec's items do not hold",
			"4 #5: restates rfc9999-4-y, which the checklist does not hold",
			"4: its rows are not numbered 1 to 4 in order",
			"rfc9999-4-c: no ledger row names it",
		]);
	});
});

describe("decisions", () => {
	it("reads decisions and refuses a malformed or repeated one", () => {
		const read = parseDecisions(
			"# Decisions\n\nIntro text.\n\n- **D-1** 2026-10-26 (owner): keep it.\n- **D-1** 2026-10-27 (owner): again.\n- **D-2** yesterday: x\n",
		);
		expect([...read.decisions.keys()]).toEqual(["D-1"]);
		expect(read.findings.map((f) => f.detail)).toEqual([
			"D-1: is written twice",
			"not a decision: - **D-2** yesterday: x",
		]);
	});
});

describe("notes", () => {
	const notes =
		"# Notes\n\n- **N-https** Production holds to https; outside it, http where declared.\n";

	it("takes a note an item points to, written once in the notes", () => {
		const text = items("## 4 X\n\n- **rfc9999-4-a** MUST: a\n  note: N-https\n");
		expect(parseItems("rfc9999", text).items[0]?.note).toBe("N-https");
		expect(findings(text, ledger("- 4 #1 MUST: rfc9999-4-a\n"), undefined, notes)).toEqual([]);
		expect(parseNotes(notes).notes.get("N-https")).toEqual({
			id: "N-https",
			text: "Production holds to https; outside it, http where declared.",
		});
	});

	it("refuses a note the notes do not hold, two notes on an item, and a line of the notes that is none", () => {
		const text = items(
			"## 4 X\n\n- **rfc9999-4-a** MUST: a\n  note: N-other\n- **rfc9999-4-b** MUST: b\n  note: N-https\n  note: N-https\n",
		);
		const rows = ledger("- 4 #1 MUST: rfc9999-4-a\n- 4 #2 MUST: rfc9999-4-b\n");
		expect(findings(text, rows, undefined, notes)).toEqual([
			"rfc9999-4-b: has more than one note line",
			"rfc9999-4-a: its note N-other is in no notes",
		]);
		expect(
			parseNotes("# Notes\n\n- N-https without its mark\n- **N-x** one\n- **N-x** two\n").findings,
		).toEqual([
			{ where: "checklist/notes.md", detail: "not a note: - N-https without its mark" },
			{ where: "checklist/notes.md", detail: "N-x: is written twice" },
		]);
	});
});
