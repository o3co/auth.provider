import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readWorkspace } from "@mod/guard-imports";
import {
	type Checklist,
	checklistFindings,
	type Finding,
	parseDecisions,
	parseItems,
	parseLedger,
	type Spec,
} from "./checklist.ts";
import type { TestRef } from "./report.ts";
import { titlesIn } from "./titles.ts";

const self = "@mod/spec-checklist";
export const checklistDir = join(import.meta.dirname, "..", "checklist");
export const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");
export const reportDir = join(repoRoot, "docs", "compliance");

/** The checklist as its files hold it: each spec's items and ledger, and the decisions. */
export function readChecklist(dir = checklistDir): Checklist {
	const files = readdirSync(dir).filter((f) => f.endsWith(".md"));
	const parsing: Finding[] = [];
	const specs: Spec[] = [];
	for (const f of files.filter((f) => !f.endsWith(".ledger.md") && f !== "decisions.md").sort()) {
		const spec = f.slice(0, -".md".length);
		const items = parseItems(spec, readFileSync(join(dir, f), "utf8"));
		const ledgerFile = `${spec}.ledger.md`;
		const ledger = files.includes(ledgerFile)
			? parseLedger(spec, readFileSync(join(dir, ledgerFile), "utf8"))
			: undefined;
		parsing.push(...items.findings, ...(ledger?.findings ?? []));
		specs.push({ spec, title: items.title, items: items.items, ledger: ledger?.ledger });
	}
	for (const f of files.filter((f) => f.endsWith(".ledger.md"))) {
		if (!files.includes(f.replace(".ledger.md", ".md")))
			parsing.push({ where: `checklist/${f}`, detail: "a ledger with no items" });
	}
	const decisions = files.includes("decisions.md")
		? parseDecisions(readFileSync(join(dir, "decisions.md"), "utf8"))
		: { decisions: new Map(), findings: [] };
	return { specs, decisions: decisions.decisions, parsing: [...parsing, ...decisions.findings] };
}

/** Every test in the workspace that names an item, by item, and each ID written where no test's title is. */
export function workspaceTests(root: string) {
	const tests = new Map<string, TestRef[]>();
	const stray: Finding[] = [];
	for (const p of readWorkspace(root).filter((p) => p.name !== self)) {
		for (const file of p.files.filter((f) => /\.(ts|mjs)$/.test(f))) {
			const read = titlesIn(
				readFileSync(join(p.dir, file), "utf8"),
				/\.(test|case)\.ts$/.test(file),
			);
			for (const id of read.stray)
				stray.push({
					where: `${p.name} ${file}`,
					detail: `${id}: an item ID outside the bracket of a test's title`,
				});
			for (const t of read.titles)
				for (const id of t.ids)
					tests.set(id, [...(tests.get(id) ?? []), { pkg: p.name, file, title: t.title }]);
		}
	}
	return { tests, stray };
}

/** The items each item updates, turned round: an item, by the items that update it. */
export function updatedByOf(c: Checklist): Map<string, string[]> {
	const by = new Map<string, string[]>();
	for (const i of c.specs.flatMap((s) => s.items))
		for (const u of i.updates) by.set(u, [...(by.get(u) ?? []), i.id]);
	return by;
}

/** Every finding over the checklist and the workspace's tests. */
export function repoFindings(c: Checklist, w: ReturnType<typeof workspaceTests>): Finding[] {
	const items = new Map(c.specs.flatMap((s) => s.items.map((i) => [i.id, i] as const)));
	const named: Finding[] = [...w.tests].flatMap(([id, refs]) => {
		const item = items.get(id);
		const where = refs.map((r) => `${r.pkg} ${r.file}`).join(", ");
		if (!item) return [{ where, detail: `${id}: names an item the checklist does not hold` }];
		if (item.mark?.kind === "out-of-scope")
			return [{ where, detail: `${id}: is out of scope, and a test names it` }];
		return [];
	});
	return [...checklistFindings(c), ...w.stray, ...named];
}
