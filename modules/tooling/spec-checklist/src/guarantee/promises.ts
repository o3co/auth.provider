import type { Finding, Spec } from "../checklist.ts";

/** A promise of the security model: its number and its bold title, as written. */
export interface Promised {
	readonly number: number;
	readonly title: string;
}

/** Where the guarantees' promises are written, as the guarantee file's source line names it. */
export const promisesSource = "docs/security-model.md#promises-across-modules";

const sectionHead = /^## Promises across modules\s*$/;
// A top-level list entry of any kind: each must be a promise written as `N. **<title>**`.
const listEntry = /^(?:\d+[.)]|[-*+])(?:\s|$)/;
const indentedNumbered = /^\s+\d+[.)](?:\s|$)/;
// The title runs to the line's last `**`, so a code span holding `**` stays whole; only blanks may follow.
const promiseEntry = /^(\d+)\. \*\*(.+)\*\*\s*$/;

/**
 * The promises of the security model's `## Promises across modules` section, read so that none is
 * lost unseen: a section not there once, a list entry not written as `N. **<title>**` (another
 * marker, an empty entry, no bold, a title running past its line, words after its title), an
 * indented numbered entry, numbers that do not run 1, 2, … and an empty section are findings. CRLF
 * reads as LF; a title keeps its punctuation and code spans. A promise's indented bullets and lines
 * are its own, and not read.
 */
export function promisesIn(text: string): { promises: Promised[]; findings: string[] } {
	const lines = text.replaceAll("\r\n", "\n").split("\n");
	const heads = lines.flatMap((line, at) => (sectionHead.test(line) ? [at] : []));
	if (heads.length !== 1)
		return {
			promises: [],
			findings: [
				`the security model has ${heads.length} sections ## Promises across modules, not one`,
			],
		};
	const start = (heads[0] ?? 0) + 1;
	const next = lines.findIndex((line, at) => at >= start && line.startsWith("## "));
	const findings: string[] = [];
	const promises: Promised[] = [];
	for (const line of lines.slice(start, next === -1 ? undefined : next)) {
		if (indentedNumbered.test(line)) findings.push(`an indented numbered entry: ${line.trim()}`);
		if (!listEntry.test(line)) continue;
		const entry = promiseEntry.exec(line);
		if (entry) promises.push({ number: Number(entry[1]), title: entry[2] ?? "" });
		else findings.push(`a list entry not written as N. **<title>**: ${line}`);
	}
	if (promises.length === 0) findings.push("the section holds no promise");
	promises.forEach((p, at) => {
		if (p.number !== at + 1) findings.push(`promise ${p.number} is written where ${at + 1} is due`);
	});
	return { promises, findings };
}

/** The guarantee file against the promises: each section a promise's number and title, word for word; every promise an item. */
export function guaranteeFindings(spec: Spec, promises: readonly Promised[]): Finding[] {
	const where = `checklist/${spec.spec}.md`;
	const findings: Finding[] = [];
	const byNumber = new Map(promises.map((p) => [String(p.number), p.title]));
	let last = 0;
	for (const [number, title] of spec.guarantee?.sections ?? new Map<string, string>()) {
		const promised = byNumber.get(number);
		if (promised === undefined)
			findings.push({
				where,
				detail: `section ${number}: the security model holds no promise ${number}`,
			});
		else if (promised !== title)
			findings.push({
				where,
				detail: `section ${number}: titled "${title}", not "${promised}" as the security model has it`,
			});
		if (Number(number) <= last)
			findings.push({ where, detail: `section ${number}: written after section ${last}` });
		last = Number(number);
	}
	for (const p of promises) {
		if (!spec.items.some((i) => i.section === String(p.number)))
			findings.push({ where, detail: `promise ${p.number}: no item holds it` });
	}
	return findings;
}
