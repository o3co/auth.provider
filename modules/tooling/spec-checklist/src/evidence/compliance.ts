import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expectedOf, packageDirs, readChecklist, workspaceTests } from "../repo.ts";
import type { EvidenceReport } from "./reporter.ts";
import { checkpoint, complianceTable, itemStatuses, selectReports } from "./runs.ts";

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

/**
 * Reads every report under `dir`, keeps this run's (`of`), and writes `compliance.json` and
 * `compliance.md` beside them: each item's status and the counts the checkpoint takes. Answers the
 * table and whether a release may go on: none failed, incomplete or unverified.
 */
export function complianceOf(
	root: string,
	dir: string,
	of: { readonly commit: string; readonly run: string },
) {
	const reports = selectReports(
		walk(dir)
			.map((f) => JSON.parse(readFileSync(f, "utf8")) as unknown)
			.filter(isReport),
		of,
	);
	const expected = expectedOf(root);
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
	const table = complianceTable(statuses, missingRuns);
	writeFileSync(
		join(dir, "compliance.json"),
		JSON.stringify({ missingRuns, checkpoint: checkpoint(statuses), items: statuses }, null, 2),
	);
	writeFileSync(join(dir, "compliance.md"), table);
	const blocking = statuses.filter((s) =>
		["failed", "incomplete", "unverified"].includes(s.status),
	);
	return { table, releasable: blocking.length === 0 && missingRuns.length === 0 };
}
