import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expectedOf, packageDirs, readChecklist, runsOf, workspaceTests } from "../repo.ts";
import type { EvidenceReport } from "./reporter.ts";
import {
	type Attempted,
	attemptsOf,
	blocksRelease,
	checkpoint,
	complianceTable,
	gateFailures,
	itemStatuses,
	selectReports,
} from "./runs.ts";

const walk = (dir: string): string[] =>
	readdirSync(dir).flatMap((f) => {
		const path = join(dir, f);
		return statSync(path).isDirectory() ? walk(path) : f.endsWith(".json") ? [path] : [];
	});

const isReport = (r: unknown): r is EvidenceReport => {
	const o = r as Partial<EvidenceReport> | null;
	return (
		typeof o?.identity?.entry === "string" && Array.isArray(o.tests) && typeof o.errors === "number"
	);
};

const isMark = (m: unknown): m is Attempted => {
	const a = (m as Partial<Attempted> | null)?.attempted;
	return typeof a?.run === "string" && typeof a.attempt === "number" && typeof a.kind === "string";
};

/** Writes this run's `compliance.json` and `compliance.md` beside its reports; answers the table and whether a release may go on. */
export function complianceOf(
	root: string,
	dir: string,
	of: { readonly commit: string; readonly run: string; readonly release: boolean },
) {
	const read = walk(dir).map((f) => JSON.parse(readFileSync(f, "utf8")) as unknown);
	const runs = runsOf(root);
	const reports = selectReports(
		read.filter(isReport),
		of,
		attemptsOf(read.filter(isMark), runs, of.run),
	);
	const expected = expectedOf(runs, of.release);
	const present = new Set(reports.map((r) => r.identity.entry));
	const missingRuns = expected.entries.filter((e) => !present.has(e));
	const items = readChecklist().specs.flatMap((s) => s.items);
	const statuses = itemStatuses(
		items,
		workspaceTests(root).tests,
		reports,
		expected,
		packageDirs(root),
	);
	const stopped = gateFailures(reports, expected.gate);
	const table = [
		complianceTable(statuses, missingRuns),
		...(stopped.length > 0
			? ["## Gate runs' failed tests", "", ...stopped.map((s) => `- ${s}`), ""]
			: []),
	].join("\n");
	writeFileSync(
		join(dir, "compliance.json"),
		JSON.stringify(
			{ missingRuns, gateFailures: stopped, checkpoint: checkpoint(statuses), items: statuses },
			null,
			2,
		),
	);
	writeFileSync(join(dir, "compliance.md"), table);
	const blocking = statuses.filter(blocksRelease);
	return {
		table,
		releasable: blocking.length === 0 && missingRuns.length === 0 && stopped.length === 0,
	};
}
