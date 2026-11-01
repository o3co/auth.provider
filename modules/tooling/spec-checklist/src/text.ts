import type { Ledger } from "./checklist.ts";
import { type Keyword, keywords } from "./ids.ts";

export interface Occurrence {
	readonly section: string;
	readonly ordinal: number;
	readonly keyword: Keyword;
}

const pageFoot = /\[Page \d+\]\s*$/;
const pageHead = /^\S.*\s{2,}\S.*\d{4}\s*$/;
const sectionHead = /^((?:\d+|Appendix [A-Z]|[A-Z])(?:\.\d+)*)\.\s+\S/;
const keyword = new RegExp(`\\b(${keywords.join("|")})\\b`, "g");

/**
 * Each requirement keyword in a spec's plain text, numbered within its section in reading order.
 * Page heads and feet are dropped and whitespace is joined, so a phrase split across lines or pages
 * is one; a section starts at a numbered heading at the line's start, an appendix's by its letter.
 */
export function occurrences(text: string): Occurrence[] {
	const sections = new Map<string, string[]>();
	let at = "front";
	for (const line of text.replaceAll("\f", "\n").split("\n")) {
		if (pageFoot.test(line) || pageHead.test(line)) continue;
		const head = sectionHead.exec(line);
		if (head) at = (head[1] ?? "").replace("Appendix ", "");
		sections.set(at, [...(sections.get(at) ?? []), line]);
	}
	return [...sections].flatMap(([section, lines]) =>
		[...lines.join(" ").replace(/\s+/g, " ").matchAll(keyword)].map((m, k) => ({
			section,
			ordinal: k + 1,
			keyword: m[1] as Keyword,
		})),
	);
}

/** Where a ledger and its spec's text differ: the text's digest, and each place either lacks or names otherwise. */
export function ledgerAgainstText(ledger: Ledger, text: string, digest: string): string[] {
	const found =
		digest === ledger.sha256 ? [] : [`the text's sha256 is ${digest}, not the ledger's`];
	const key = (o: { section: string; ordinal: number }) => `${o.section} #${o.ordinal}`;
	const counts = new Map<string, number>();
	for (const r of ledger.rows) counts.set(key(r), (counts.get(key(r)) ?? 0) + 1);
	for (const [place, n] of counts)
		if (n > 1) found.push(`${place}: the ledger has ${n} rows for it`);
	const rows = new Map(ledger.rows.map((r) => [key(r), r.keyword]));
	const places = occurrences(text);
	for (const o of places) {
		const written = rows.get(key(o));
		if (written === undefined)
			found.push(`${key(o)}: the text has ${o.keyword}, the ledger has no row`);
		else if (written !== o.keyword)
			found.push(`${key(o)}: the text has ${o.keyword}, the ledger ${written}`);
	}
	const inText = new Set(places.map(key));
	for (const r of ledger.rows) {
		if (!inText.has(key(r)))
			found.push(`${key(r)}: the ledger has ${r.keyword}, the text has no such place`);
	}
	return found;
}
