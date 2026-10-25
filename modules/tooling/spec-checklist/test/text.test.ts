import { describe, expect, it } from "vitest";
import type { LedgerRow } from "../src/checklist.ts";
import { ledgerAgainstText, occurrences } from "../src/text.ts";

const page = (n: number) =>
	`Author                     Standards Track                 [Page ${n}]\f\nRFC 9999                     Example                         May 2026\n`;

const text = [
	"Abstract",
	"",
	"   This document SHOULD be read.",
	"",
	"Table of Contents",
	"",
	"   1.  Introduction ..................................... 2",
	"",
	"1.  Introduction",
	"",
	"   The server MUST answer.  It MUST",
	page(1),
	"   NOT wait, and it is NOT RECOMMENDED to sleep.",
	"",
	"1.1.  Terms",
	"",
	'   The key words "MUST" and "SHOULD NOT" are as in RFC 2119.',
	"",
	"Appendix A.  Extra",
	"",
	"   A server SHALL log.",
	"",
	"A.1.  More",
	"",
	"   It is REQUIRED.",
].join("\n");

describe("occurrences", () => {
	it("numbers each keyword within its section, across lines and pages, the longer phrase first", () => {
		expect(occurrences(text)).toEqual([
			{ section: "front", ordinal: 1, keyword: "SHOULD" },
			{ section: "1", ordinal: 1, keyword: "MUST" },
			{ section: "1", ordinal: 2, keyword: "MUST NOT" },
			{ section: "1", ordinal: 3, keyword: "NOT RECOMMENDED" },
			{ section: "1.1", ordinal: 1, keyword: "MUST" },
			{ section: "1.1", ordinal: 2, keyword: "SHOULD NOT" },
			{ section: "A", ordinal: 1, keyword: "SHALL" },
			{ section: "A.1", ordinal: 1, keyword: "REQUIRED" },
		]);
	});
});

describe("ledgerAgainstText", () => {
	const excluded = { kind: "excluded", category: "definition" } as const;
	const rows: LedgerRow[] = occurrences(text).map((o) => ({ ...o, to: excluded }));
	const at = (k: number): LedgerRow =>
		rows[k] ?? { section: "", ordinal: 0, keyword: "MUST", to: excluded };
	const digest = "9b1c4f4a6d2e0d8a4a7a7b8f3fb4b4a0c8f2e1c6d4a5b3e2f1a0c9d8e7f6a5b4";

	it("finds nothing where the rows are the text's occurrences and the digest is the text's", () => {
		const ledger = { source: "x", version: "x", sha256: digest, rows };
		expect(ledgerAgainstText(ledger, text, digest)).toEqual([]);
	});

	it("names a place the ledger writes twice, which no text can match", () => {
		const twice: LedgerRow[] = [...rows, at(0)];
		const ledger = { source: "x", version: "x", sha256: digest, rows: twice };
		expect(ledgerAgainstText(ledger, text, digest)).toEqual([
			"front #1: the ledger has 2 rows for it",
		]);
	});

	it("names a missing row, an extra one, one whose keyword differs, and another digest", () => {
		const changed: LedgerRow[] = [
			...rows.slice(0, 2),
			{ ...at(2), keyword: "MUST" },
			...rows.slice(4),
			{ section: "9", ordinal: 1, keyword: "MUST", to: excluded },
		];
		const ledger = { source: "x", version: "x", sha256: "b".repeat(64), rows: changed };
		expect(ledgerAgainstText(ledger, text, digest)).toEqual([
			`the text's sha256 is ${digest}, not the ledger's`,
			"1 #2: the text has MUST NOT, the ledger MUST",
			"1 #3: the text has NOT RECOMMENDED, the ledger has no row",
			"9 #1: the ledger has MUST, the text has no such place",
		]);
	});
});
