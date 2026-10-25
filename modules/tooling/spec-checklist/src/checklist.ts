import { classOf, itemId, type Keyword, keywords, type Strength, specOf } from "./ids.ts";

export type Mark =
	| { readonly kind: "out-of-scope"; readonly reason: string }
	| { readonly kind: "deviates"; readonly decision: string }
	| { readonly kind: "noncompliant"; readonly issue: string };

export interface Item {
	readonly id: string;
	readonly spec: string;
	readonly section: string;
	readonly strength: Strength;
	readonly text: string;
	readonly mark?: Mark;
	/** The items of an earlier spec this one updates. */
	readonly updates: readonly string[];
}

export const exclusions = [
	"client-only",
	"rs-only",
	"definition",
	"iana",
	"example",
	"deployment",
	"not-a-bearer-route",
	"restates",
	"other",
] as const;
export type Exclusion = (typeof exclusions)[number];
const withReason: readonly Exclusion[] = ["not-a-bearer-route", "restates", "other"];

export interface LedgerRow {
	readonly section: string;
	readonly ordinal: number;
	readonly keyword: Keyword;
	readonly to:
		| { readonly kind: "items"; readonly ids: readonly string[] }
		| { readonly kind: "excluded"; readonly category: Exclusion; readonly detail?: string };
}

export interface Ledger {
	readonly source: string;
	readonly version: string;
	readonly sha256: string;
	readonly rows: readonly LedgerRow[];
}

export interface Decision {
	readonly id: string;
	readonly date: string;
	readonly by: string;
	readonly text: string;
}

export interface Finding {
	readonly where: string;
	readonly detail: string;
}

export interface Spec {
	readonly spec: string;
	readonly title: string;
	readonly items: readonly Item[];
	readonly ledger: Ledger | undefined;
}

export interface Checklist {
	readonly specs: readonly Spec[];
	readonly decisions: ReadonlyMap<string, Decision>;
	/** What reading the files found. */
	readonly parsing: readonly Finding[];
}

const section = "(?:\\d+|[A-Z])(?:\\.\\d+)*";
const itemLine = /^- \*\*(\S+?)\*\* (MUST NOT|MUST|SHOULD NOT|SHOULD): (\S.*)$/;
const markLine = /^ {2}(out-of-scope|deviates|noncompliant|updates): (\S.*)$/;
const heading = new RegExp(`^## (${section}) \\S`);

export function parseItems(spec: string, text: string) {
	const where = `checklist/${spec}.md`;
	const findings: Finding[] = [];
	const found = (detail: string) => findings.push({ where, detail });
	const items: { -readonly [K in keyof Item]: Item[K] }[] = [];
	let title = "";
	let current: string | undefined;
	// The item a mark belongs to: the last one written in the section, none after a heading or a refused item.
	let last: (typeof items)[number] | undefined;
	let updated = false;
	for (const line of text.split("\n")) {
		const item = itemLine.exec(line);
		const mark = markLine.exec(line);
		const sectionHead = heading.exec(line);
		if (line.trim() === "") continue;
		if (line.startsWith("# ") && title === "") title = line.slice(2);
		else if (sectionHead) {
			current = sectionHead[1] ?? "";
			last = undefined;
		} else if (item) {
			const [, id = "", strength = "", text = ""] = item;
			const parts = itemId.exec(id);
			last = undefined;
			updated = false;
			if (!parts) found(`${id}: not an item ID`);
			else if (parts[1] !== spec) found(`${id}: names another spec than its file`);
			else if (current === undefined) found(`${id}: is written under no section heading`);
			else if (parts[2] !== current)
				found(`${id}: is not of section ${current}, under which it is written`);
			else if (items.some((i) => i.id === id)) found(`${id}: is written twice`);
			else {
				last = { id, spec, section: current, strength: strength as Strength, text, updates: [] };
				items.push(last);
			}
		} else if (mark) {
			const [, kind, value = ""] = mark;
			if (!last) found(`a mark with no item before it: ${line.trim()}`);
			else if (kind === "updates" && updated) found(`${last.id}: has more than one updates line`);
			else if (kind === "updates") {
				last.updates = value.split(",").map((s) => s.trim());
				updated = true;
			} else if (last.mark)
				found(`${last.id}: has more than one of out-of-scope, deviates and noncompliant`);
			else
				last.mark =
					kind === "out-of-scope"
						? { kind, reason: value }
						: kind === "deviates"
							? { kind, decision: value }
							: { kind: "noncompliant", issue: value };
		} else found(`not an item, a heading, a mark or a blank line: ${line}`);
	}
	return { title, items: items as Item[], findings };
}

const rowLine = new RegExp(`^- (front|${section}) #(\\d+) (${keywords.join("|")}): (\\S.*)$`);

export function parseLedger(spec: string, text: string) {
	const where = `checklist/${spec}.ledger.md`;
	const findings: Finding[] = [];
	const head = new Map<string, string>();
	const rows: LedgerRow[] = [];
	for (const line of text.split("\n")) {
		const meta = /^- (source|version|sha256): (\S.*)$/.exec(line);
		const row = rowLine.exec(line);
		if (meta) head.set(meta[1] ?? "", meta[2] ?? "");
		else if (row) {
			const [, at = "", n = "", keyword, target = ""] = row;
			const place = `${at} #${n}`;
			const base = { section: at, ordinal: Number(n), keyword: keyword as Keyword };
			const excluded = /^excluded (restates) (\S+)$|^excluded ([a-z-]+)(?:: (.+))?$/.exec(target);
			if (!excluded) {
				rows.push({ ...base, to: { kind: "items", ids: target.split(",").map((s) => s.trim()) } });
				continue;
			}
			const category = (excluded[1] ?? excluded[3]) as Exclusion;
			const detail = excluded[2] ?? excluded[4];
			if (!exclusions.includes(category))
				findings.push({
					where,
					detail: `${place}: excluded as ${category}, which is no exclusion`,
				});
			else if (withReason.includes(category) && !detail)
				findings.push({ where, detail: `${place}: ${category} needs its reason` });
			else
				rows.push({ ...base, to: { kind: "excluded", category, ...(detail ? { detail } : {}) } });
		} else if (line.startsWith("- ")) findings.push({ where, detail: `not a ledger row: ${line}` });
	}
	if (!head.get("source")) findings.push({ where, detail: "has no source" });
	if (!head.get("version")) findings.push({ where, detail: "has no version" });
	if (!/^[0-9a-f]{64}$/.test(head.get("sha256") ?? ""))
		findings.push({ where, detail: "has no sha256 of 64 hex digits" });
	const ledger: Ledger = {
		source: head.get("source") ?? "",
		version: head.get("version") ?? "",
		sha256: head.get("sha256") ?? "",
		rows,
	};
	return { ledger, findings };
}

export function parseDecisions(text: string) {
	const findings: Finding[] = [];
	const decisions = new Map<string, Decision>();
	for (const line of text.split("\n")) {
		if (!line.startsWith("- ")) continue;
		const d = /^- \*\*(D-\d+)\*\* (\d{4}-\d{2}-\d{2}) \(([^)]+)\): (\S.*)$/.exec(line);
		const [, id = "", date = "", by = "", what = ""] = d ?? [];
		const where = "checklist/decisions.md";
		if (!d) findings.push({ where, detail: `not a decision: ${line}` });
		else if (decisions.has(id)) findings.push({ where, detail: `${id}: is written twice` });
		else decisions.set(id, { id, date, by, text: what });
	}
	return { decisions, findings };
}

/** Every finding over the read checklist: its marks, its updates, and each ledger against its items. */
export function checklistFindings(c: Checklist): Finding[] {
	const findings = [...c.parsing];
	const all = new Map(c.specs.flatMap((s) => s.items.map((i) => [i.id, i] as const)));
	for (const s of c.specs) {
		if (!s.ledger)
			findings.push({ where: `checklist/${s.spec}.md`, detail: `${s.spec}: has no ledger` });
	}
	for (const i of c.specs.flatMap((s) => s.items)) {
		const at = (detail: string) => findings.push({ where: i.id, detail: `${i.id}: ${detail}` });
		if (i.mark?.kind === "deviates" && classOf(i.strength) === "MUST")
			at("deviates is for a SHOULD alone; a MUST not met is noncompliant");
		if (i.mark?.kind === "noncompliant" && classOf(i.strength) === "SHOULD")
			at("noncompliant is for a MUST alone");
		if (i.mark?.kind === "deviates" && !c.decisions.has(i.mark.decision))
			at(`names the decision ${i.mark.decision}, which the decisions do not hold`);
		for (const u of i.updates) {
			const earlier = all.get(u);
			if (specOf(u) === i.spec) at(`updates ${u}, an item of its own spec`);
			else if (!earlier) at(`updates ${u}, which the checklist does not hold`);
			else if (classOf(earlier.strength) === "MUST" && classOf(i.strength) === "SHOULD")
				at(`updates ${u}, a ${earlier.strength}, and is weaker than it`);
		}
	}
	for (const s of c.specs) if (s.ledger) findings.push(...ledgerFindings(s, s.ledger, all));
	return findings;
}

function ledgerFindings(s: Spec, ledger: Ledger, all: ReadonlyMap<string, Item>): Finding[] {
	const where = `checklist/${s.spec}.ledger.md`;
	const findings: Finding[] = [];
	const own = new Map(s.items.map((i) => [i.id, i]));
	const named = new Set<string>();
	const bySection = new Map<string, number[]>();
	for (const r of ledger.rows) {
		const place = `${r.section} #${r.ordinal}`;
		bySection.set(r.section, [...(bySection.get(r.section) ?? []), r.ordinal]);
		if (r.to.kind === "excluded") {
			const restated = r.to.category === "restates" ? all.get(r.to.detail ?? "") : undefined;
			if (r.to.category === "restates" && !restated)
				findings.push({
					where,
					detail: `${place}: restates ${r.to.detail}, which the checklist does not hold`,
				});
			else if (restated && classOf(r.keyword) !== classOf(restated.strength))
				findings.push({
					where,
					detail: `${place}: ${r.keyword} restates ${restated.id}, a ${restated.strength}`,
				});
			continue;
		}
		for (const id of r.to.ids) {
			const item = own.get(id);
			named.add(id);
			if (!item)
				findings.push({
					where,
					detail: `${place}: names ${id}, which the spec's items do not hold`,
				});
			else if (classOf(r.keyword) !== classOf(item.strength))
				findings.push({ where, detail: `${place}: ${r.keyword} names ${id}, a ${item.strength}` });
		}
	}
	for (const [at, ordinals] of bySection) {
		if (ordinals.some((n, k) => n !== k + 1))
			findings.push({
				where,
				detail: `${at}: its rows are not numbered 1 to ${ordinals.length} in order`,
			});
	}
	for (const i of s.items) {
		if (!named.has(i.id)) findings.push({ where, detail: `${i.id}: no ledger row names it` });
	}
	return findings;
}
