import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { EvidenceReport } from "../reporter.ts";

const main = join(import.meta.dirname, "..", "..", "main.ts");

const report = (commit: string): EvidenceReport => ({
	identity: { commit, run: "r1", attempt: 1, job: "checks", entry: "unit", target: "new" },
	errors: 0,
	tests: [
		{
			file: "modules/x/x/test/x.test.ts",
			names: ["revokes [rfc7009-2-a]"],
			state: "passed",
		},
	],
});

/** `run compliance` over a directory holding this run's unit report and another commit's. */
function compliance(release: boolean, marks: readonly unknown[] = []) {
	const dir = mkdtempSync(join(tmpdir(), "spec-compliance-"));
	for (const [k, m] of marks.entries())
		writeFileSync(join(dir, `attempted-${k}.json`), JSON.stringify(m));
	writeFileSync(join(dir, "unit-new-1.json"), JSON.stringify(report("c1")));
	writeFileSync(join(dir, "unit-new-2.json"), JSON.stringify(report("c0")));
	const ran = spawnSync(
		process.execPath,
		[main, "compliance", dir, ...(release ? ["--release"] : [])],
		{
			encoding: "utf8",
			env: { ...process.env, SPEC_EVIDENCE_COMMIT: "c1", GITHUB_RUN_ID: "r1" },
		},
	);
	const written = JSON.parse(readFileSync(join(dir, "compliance.json"), "utf8")) as {
		missingRuns: string[];
		items: { id: string; evidence: { commit: string; entry: string; passed: number }[] }[];
	};
	return { ran, written, table: readFileSync(join(dir, "compliance.md"), "utf8") };
}

describe("run compliance, from the reports to the table", { timeout: 120_000 }, () => {
	it("writes the table and its provenance, and only tells where the run is no release's", () => {
		const { ran, written, table } = compliance(false);
		expect(ran.status).toBe(0);
		expect(written.missingRuns).toContain("integration");
		expect(written.missingRuns).toContain("@mod/conformance-code@full");
		expect(written.missingRuns).not.toContain("unit");
		expect(written.missingRuns).not.toContain("@mod/conformance-recipes");
		// The other commit's report is not this run's evidence.
		expect(written.items.find((i) => i.id === "rfc7009-2-a")?.evidence).toEqual([
			{
				commit: "c1",
				run: "r1",
				attempt: 1,
				job: "checks",
				entry: "unit",
				passed: 1,
				failed: 0,
				skipped: 0,
			},
		]);
		expect(table).toContain("# Compliance of this run");
		expect(table).toContain("| Role | Class |");
	});

	it("takes no report of an earlier attempt where the job was attempted again and did not report", () => {
		const { written } = compliance(false, [
			{ attempted: { run: "r1", attempt: 2, job: "checks", kind: "unit" } },
		]);
		expect(written.missingRuns).toContain("unit");
		expect(written.items.find((i) => i.id === "rfc7009-2-a")?.evidence).toEqual([]);
	});

	it("fails a release's run that lacks a run's report, a release's own among them", () => {
		const { ran, written } = compliance(true);
		expect(ran.status).toBe(1);
		expect(written.missingRuns).toContain("@mod/conformance-recipes");
	});
});
