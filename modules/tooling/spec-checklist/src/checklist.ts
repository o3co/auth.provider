import { type FaultName, faultNames, isFaultName } from "./guarantee/faults.ts";
import { promisesSource } from "./guarantee/promises.ts";
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
	/** The shared note it points to, by its id in `checklist/notes.md`. */
	readonly note?: string;
	readonly updates: readonly string[];
	/** The role of the server's the requirement binds. */
	readonly role: Role;
	/** A guarantee's faults: each a column its tests must hold, marked `{fault:<name>}`. */
	readonly faults?: readonly FaultName[];
}

/** What the guarantee file holds besides its items: its source lines, the faults it gives a meaning, and each section's title. */
export interface GuaranteeHead {
	readonly sources: readonly string[];
	readonly meanings: readonly string[];
	readonly sections: ReadonlyMap<string, string>;
}

/** The spec of the provider's own promises, held to the security model rather than a ledger. */
export const guaranteeSpec = "guarantee";

/**
 * The roles the server takes: authorization server, OpenID Provider, resource server at its own
 * protected routes, relying party to an upstream IdP, and client sending tokens or assertions out.
 */
export const roles = ["as", "op", "rs", "rp", "client"] as const;
export type Role = (typeof roles)[number];

/** A spec's default role: an OpenID spec's is the OpenID Provider's, an RFC's the authorization server's. */
export const defaultRoleOf = (spec: string): Role => (spec.startsWith("oidc-") ? "op" : "as");

export const exclusions = [
	"client-only",
	"rs-only",
	"definition",
	"iana",
	"example",
	"deployment",
	"not-a-bearer-route",
	"restates",
	"other-role",
	"other",
] as const;
export type Exclusion = (typeof exclusions)[number];
const withReason: readonly Exclusion[] = ["not-a-bearer-route", "other-role", "restates", "other"];

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
	readonly guarantee?: GuaranteeHead;
}

export interface Checklist {
	readonly specs: readonly Spec[];
	readonly decisions: ReadonlyMap<string, Decision>;
	/** The notes items point to, by id; none where the checklist has no notes file. */
	readonly notes?: ReadonlyMap<string, Note>;
	/** What reading the files found. */
	readonly parsing: readonly Finding[];
}

const section = "(?:\\d+|[A-Z])(?:\\.\\d+)*";
const itemLine = /^- \*\*(\S+?)\*\* (MUST NOT|MUST|SHOULD NOT|SHOULD): (\S.*)$/;
const markLine = /^ {2}(out-of-scope|deviates|noncompliant|updates|role|faults|note): (\S.*)$/;
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
	let roled = false;
	let role = defaultRoleOf(spec);
	let headRoled = false;
	const guaranteed = spec === guaranteeSpec;
	const sources: string[] = [];
	const meanings: string[] = [];
	const sections = new Map<string, string>();
	for (const line of text.split("\n")) {
		const item = itemLine.exec(line);
		const mark = markLine.exec(line);
		const sectionHead = heading.exec(line);
		if (line.trim() === "") continue;
		const head = /^- role: (\S+)$/.exec(line);
		const source = /^- source: (\S.*)$/.exec(line);
		const meaning = /^- fault (\S+): \S/.exec(line);
		const promise = /^## (\S+) (\S.*)$/.exec(line);
		if (line.startsWith("# ") && title === "") title = line.slice(2);
		else if (guaranteed && current === undefined && (source || meaning)) {
			if (source) sources.push(source[1] ?? "");
			if (meaning) meanings.push(meaning[1] ?? "");
		} else if (guaranteed && head) found("a guarantee takes no role line");
		else if (guaranteed && promise) {
			const [, number = "", heading = ""] = promise;
			if (!/^\d+$/.test(number)) found(`section ${number}: not a promise's number`);
			else if (/\s#+\s*$/.test(heading)) found(`section ${number}: a heading closed by #`);
			else if (sections.has(number)) found(`section ${number}: written twice`);
			else sections.set(number, heading);
			current = /^\d+$/.test(number) ? number : undefined;
			last = undefined;
		} else if (head && current === undefined) {
			const given = head[1] as Role;
			if (headRoled) found("the file has more than one role line");
			else if (roles.includes(given)) role = given;
			else found(`the file's role ${given} is none of ${roles.join(", ")}`);
			headRoled = true;
		} else if (sectionHead) {
			current = sectionHead[1] ?? "";
			last = undefined;
		} else if (item) {
			const [, id = "", strength = "", text = ""] = item;
			const parts = itemId.exec(id);
			last = undefined;
			updated = false;
			roled = false;
			if (!parts) found(`${id}: not an item ID`);
			else if (parts[1] !== spec) found(`${id}: names another spec than its file`);
			else if (current === undefined) found(`${id}: is written under no section heading`);
			else if (parts[2] !== current)
				found(`${id}: is not of section ${current}, under which it is written`);
			else if (items.some((i) => i.id === id)) found(`${id}: is written twice`);
			else {
				last = {
					id,
					spec,
					section: current,
					strength: strength as Strength,
					text,
					updates: [],
					role,
				};
				items.push(last);
			}
		} else if (mark) {
			const [, kind, value = ""] = mark;
			if (!last) found(`a mark with no item before it: ${line.trim()}`);
			else if (kind === "faults") {
				const names = value.split(",").map((n) => n.trim());
				if (!guaranteed) found(`${last.id}: a faults line is a guarantee's alone`);
				else if (last.faults) found(`${last.id}: has more than one faults line`);
				else if (names.some((n) => !isFaultName(n)))
					found(`${last.id}: faults ${value} names a fault none of ${faultNames.join(", ")}`);
				else if (new Set(names).size !== names.length)
					found(`${last.id}: faults ${value} names one twice`);
				else last.faults = names as FaultName[];
			} else if (guaranteed && (kind === "role" || kind === "updates"))
				found(`${last.id}: a guarantee takes no ${kind} line`);
			else if (kind === "role" && roled) found(`${last.id}: has more than one role line`);
			else if (kind === "role") {
				// A role line seen, taken or not, so a second one is refused either way.
				roled = true;
				if (roles.includes(value as Role)) last.role = value as Role;
				else found(`${last.id}: its role ${value} is none of ${roles.join(", ")}`);
			} else if (kind === "note" && last.note) found(`${last.id}: has more than one note line`);
			else if (kind === "note") last.note = value;
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
	const guarantee = guaranteed ? { sources, meanings, sections } : undefined;
	return { title, items: items as Item[], findings, ...(guarantee ? { guarantee } : {}) };
}

/** The guarantee file's own rules: one source naming the promises and no ledger, a meaning for each fault and no other, MUST alone, noncompliant alone. */
function guaranteeRules(s: Spec): Finding[] {
	const where = `checklist/${s.spec}.md`;
	const findings: Finding[] = [];
	const sources = s.guarantee?.sources ?? [];
	if (sources.length !== 1 || sources[0] !== promisesSource)
		findings.push({
			where,
			detail: `needs one source line, ${promisesSource}; has ${sources.join(", ") || "none"}`,
		});
	if (s.ledger)
		findings.push({
			where: `checklist/${s.spec}.ledger.md`,
			detail: "a guarantee is held to the security model, and takes no ledger",
		});
	const meanings = s.guarantee?.meanings ?? [];
	for (const name of faultNames) {
		const given = meanings.filter((m) => m === name).length;
		if (given !== 1)
			findings.push({ where, detail: `fault ${name}: has ${given} meaning lines, not one` });
	}
	for (const m of meanings.filter((m) => !isFaultName(m)))
		findings.push({ where, detail: `fault ${m}: a meaning for a fault the package does not name` });
	for (const i of s.items) {
		if (classOf(i.strength) !== "MUST")
			findings.push({ where: i.id, detail: `${i.id}: a guarantee is a MUST or a MUST NOT` });
		if (i.mark && i.mark.kind !== "noncompliant")
			findings.push({
				where: i.id,
				detail: `${i.id}: a guarantee takes noncompliant alone, not ${i.mark.kind}`,
			});
	}
	return findings;
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

/** A note several items point to, written once: `- **N-<name>** <text>`. */
export interface Note {
	readonly id: string;
	readonly text: string;
}

export function parseNotes(text: string) {
	const findings: Finding[] = [];
	const notes = new Map<string, Note>();
	for (const line of text.split("\n")) {
		if (!line.startsWith("- ")) continue;
		const n = /^- \*\*(N-[a-z0-9-]+)\*\* (\S.*)$/.exec(line);
		const [, id = "", what = ""] = n ?? [];
		const where = "checklist/notes.md";
		if (!n) findings.push({ where, detail: `not a note: ${line}` });
		else if (notes.has(id)) findings.push({ where, detail: `${id}: is written twice` });
		else notes.set(id, { id, text: what });
	}
	return { notes, findings };
}

/** Every finding over the read checklist: its marks, its updates, and each ledger against its items. */
export function checklistFindings(c: Checklist): Finding[] {
	const findings = [...c.parsing];
	const all = new Map(c.specs.flatMap((s) => s.items.map((i) => [i.id, i] as const)));
	for (const s of c.specs) {
		if (s.spec === guaranteeSpec) findings.push(...guaranteeRules(s));
		else if (!s.ledger)
			findings.push({ where: `checklist/${s.spec}.md`, detail: `${s.spec}: has no ledger` });
	}
	for (const i of c.specs.flatMap((s) => s.items)) {
		const at = (detail: string) => findings.push({ where: i.id, detail: `${i.id}: ${detail}` });
		if (i.mark?.kind === "deviates" && classOf(i.strength) === "MUST")
			at("deviates is for a SHOULD alone; a MUST not met is noncompliant");
		if (i.mark?.kind === "noncompliant" && classOf(i.strength) === "SHOULD")
			at("noncompliant is for a MUST alone");
		if (i.note !== undefined && !c.notes?.has(i.note)) at(`its note ${i.note} is in no notes`);
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
