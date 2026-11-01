import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { readWorkspace } from "@mod/guard-imports";
import {
	type Checklist,
	checklistFindings,
	type Finding,
	guaranteeSpec,
	parseDecisions,
	parseItems,
	parseLedger,
	parseNotes,
	type Spec,
} from "./checklist.ts";
import { type Expected, type Run, runsPrinted } from "./evidence/runs.ts";
import { guaranteeFindings, promisesIn } from "./guarantee/promises.ts";
import { specOf } from "./ids.ts";
import type { TestRef } from "./report.ts";
import { titlesIn } from "./titles.ts";

const self = "@mod/spec-checklist";
// Each may be named elsewhere, so a command can be run over a checklist and a place of a test's own.
export const checklistDir =
	process.env.SPEC_CHECKLIST_DIR ?? join(import.meta.dirname, "..", "checklist");
export const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");
export const reportDir =
	process.env.SPEC_CHECKLIST_REPORT_DIR ?? join(repoRoot, "docs", "compliance");
/** The security model, whose promises the guarantee file is held to. */
export const securityModel = join(repoRoot, "docs", "security-model.md");

/** The checklist as its files hold it: each spec's items and ledger, and the decisions. */
export function readChecklist(dir = checklistDir, model = securityModel): Checklist {
	const files = readdirSync(dir).filter((f) => f.endsWith(".md"));
	const parsing: Finding[] = [];
	const specs: Spec[] = [];
	// The files that are no spec: what several specs share, and the directory's own guide to the forms.
	const shared = ["decisions.md", "notes.md", "README.md"];
	for (const f of files.filter((f) => !f.endsWith(".ledger.md") && !shared.includes(f)).sort()) {
		const spec = f.slice(0, -".md".length);
		const items = parseItems(spec, readFileSync(join(dir, f), "utf8"));
		const ledgerFile = `${spec}.ledger.md`;
		const ledger = files.includes(ledgerFile)
			? parseLedger(spec, readFileSync(join(dir, ledgerFile), "utf8"))
			: undefined;
		parsing.push(...items.findings, ...(ledger?.findings ?? []));
		const read: Spec = {
			spec,
			title: items.title,
			items: items.items,
			ledger: ledger?.ledger,
			...(items.guarantee ? { guarantee: items.guarantee } : {}),
		};
		specs.push(read);
		if (spec === guaranteeSpec) {
			const promised = promisesIn(readFileSync(model, "utf8"));
			parsing.push(
				...promised.findings.map((detail) => ({ where: "docs/security-model.md", detail })),
			);
			parsing.push(...guaranteeFindings(read, promised.promises));
		}
	}
	for (const f of files.filter((f) => f.endsWith(".ledger.md"))) {
		if (!files.includes(f.replace(".ledger.md", ".md")))
			parsing.push({ where: `checklist/${f}`, detail: "a ledger with no items" });
	}
	const decisions = files.includes("decisions.md")
		? parseDecisions(readFileSync(join(dir, "decisions.md"), "utf8"))
		: { decisions: new Map(), findings: [] };
	const notes = files.includes("notes.md")
		? parseNotes(readFileSync(join(dir, "notes.md"), "utf8"))
		: { notes: new Map(), findings: [] };
	return {
		specs,
		decisions: decisions.decisions,
		notes: notes.notes,
		parsing: [...parsing, ...decisions.findings, ...notes.findings],
	};
}

/** Every test in the workspace that names an item, by item, and each ID written where no test's title is. */
/** Whether a file holds tests: a `.test.ts` or `.case.ts` file, or any file under a `test` directory. */
export const holdsTests = (file: string) =>
	/\.(test|case)\.ts$/.test(file) || /(^|\/)test\//.test(file);

export function workspaceTests(root: string) {
	const tests = new Map<string, TestRef[]>();
	const stray: Finding[] = [];
	const marks: Finding[] = [];
	for (const p of readWorkspace(root).filter((p) => p.name !== self)) {
		for (const file of p.files.filter((f) => /\.(ts|mjs)$/.test(f))) {
			const read = titlesIn(readFileSync(join(p.dir, file), "utf8"), holdsTests(file));
			for (const id of read.stray)
				stray.push({
					where: `${p.name} ${file}`,
					detail: `${id}: an item ID outside the bracket of a test's title`,
				});
			for (const t of read.titles) {
				const where = `${p.name} ${file}`;
				for (const m of t.malformed)
					marks.push({ where, detail: `${t.title}: a malformed fault mark ${m}` });
				if (t.faults.length > 0 && !t.ids.some((id) => specOf(id) === guaranteeSpec))
					marks.push({ where, detail: `${t.title}: marks a fault and names no guarantee` });
				for (const id of t.ids)
					tests.set(id, [
						...(tests.get(id) ?? []),
						{
							pkg: p.name,
							file,
							title: t.title,
							path: t.path,
							suite: t.suite,
							...(t.faults.length > 0 ? { faults: t.faults } : {}),
						},
					]);
			}
		}
	}
	return { tests, stray, marks };
}

/** The items each item updates, turned round: an item, by the items that update it. */
export function updatedByOf(c: Checklist): Map<string, string[]> {
	const by = new Map<string, string[]>();
	for (const i of c.specs.flatMap((s) => s.items))
		for (const u of i.updates) by.set(u, [...(by.get(u) ?? []), i.id]);
	return by;
}

/** Every finding over the checklist and the workspace's tests. */
export function repoFindings(
	c: Checklist,
	w: {
		readonly tests: ReadonlyMap<string, readonly TestRef[]>;
		readonly stray: readonly Finding[];
		readonly marks?: readonly Finding[];
	},
): Finding[] {
	const items = new Map(c.specs.flatMap((s) => s.items.map((i) => [i.id, i] as const)));
	const named: Finding[] = [...w.tests].flatMap(([id, refs]) => {
		const item = items.get(id);
		const where = refs.map((r) => `${r.pkg} ${r.file}`).join(", ");
		if (!item) return [{ where, detail: `${id}: names an item the checklist does not hold` }];
		if (item.mark?.kind === "out-of-scope")
			return [{ where, detail: `${id}: is out of scope, and a test names it` }];
		// A mark binds to every guarantee its title names, whose faults line must hold it: one taken off
		// the line, or the line taken away, leaves its tests a finding rather than quietly loosened.
		if (item.spec !== guaranteeSpec) return [];
		return refs.flatMap((r) =>
			(r.faults ?? [])
				.filter((f) => !((item.faults ?? []) as readonly string[]).includes(f))
				.map((f) => ({
					where: `${r.pkg} ${r.file}`,
					detail: `${id}: ${r.title} marks the fault ${f}, which its faults line does not name`,
				})),
		);
	});
	return [...checklistFindings(c), ...w.stray, ...(w.marks ?? []), ...named];
}

const scriptsOf = (p: ReturnType<typeof readWorkspace>[number]) =>
	(p.manifest as { readonly scripts?: Readonly<Record<string, string>> }).scripts ?? {};

/**
 * Every run a CI run makes: the root's unit and integration runs, each package with a `conformance`
 * script on the new system (an area), and every run a package's `evidence-runs` script prints as a
 * JSON list of runs (a pattern's as `<package>@<pattern>`, a harness's as `<package>#<run>`).
 */
export function runsOf(root: string): Run[] {
	const packages = readWorkspace(root);
	const areas = packages
		.filter((p) => scriptsOf(p).conformance)
		.map((p): Run => ({ entry: p.name, kind: "area", matrix: p.name }));
	const printed = packages
		.filter((p) => scriptsOf(p)["evidence-runs"])
		.flatMap((p) =>
			runsPrinted(
				p.name,
				JSON.parse(
					execFileSync("pnpm", ["--silent", "--filter", p.name, "run", "evidence-runs"], {
						cwd: root,
						encoding: "utf8",
					}),
				),
			),
		);
	return [
		{ entry: "unit", kind: "unit" },
		{ entry: "integration", kind: "integration" },
		...areas,
		...printed,
	];
}

/** The runs a CI run must report: every run, but those only a release makes unless it is one. */
export function expectedOf(runs: readonly Run[], release: boolean): Expected {
	const entries = runs.filter((r) => release || !r.releaseOnly).map((r) => r.entry);
	const areas = new Set(runs.filter((r) => r.kind === "area").map((r) => r.entry));
	const pkgOf = (entry: string) => /^@?[^@#]+/.exec(entry)?.[0] ?? entry;
	// Every run keeps its files and its package, a release's own too where this is none: the entries
	// expected decide what must report.
	const harness = new Map<string, string[]>();
	for (const run of runs.filter((r) => r.entry.includes("#") && r.files === undefined)) {
		const pkg = pkgOf(run.entry);
		harness.set(pkg, [...(harness.get(pkg) ?? []), run.entry]);
	}
	const suffixed = runs.flatMap((r) =>
		r.files === undefined ? [] : [{ entry: r.entry, pkg: pkgOf(r.entry), files: r.files }],
	);
	const noSkip = new Set(runs.filter((r) => r.noSkip).map((r) => r.entry));
	const gate = new Set(runs.filter((r) => r.gate).map((r) => r.entry));
	return { entries, areas, runsOf: harness, suffixed, noSkip, gate };
}

/** Each workspace package's directory, relative to the root. */
export const packageDirs = (root: string) =>
	new Map(readWorkspace(root).map((p) => [p.name, relative(root, p.dir)]));
