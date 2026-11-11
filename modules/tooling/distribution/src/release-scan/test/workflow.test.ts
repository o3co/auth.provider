import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

interface Step {
	readonly run?: string;
	readonly uses?: string;
	readonly with?: Record<string, unknown>;
}
interface Job {
	readonly needs?: string | readonly string[];
	readonly permissions?: Record<string, string>;
	readonly "timeout-minutes"?: unknown;
	readonly "continue-on-error"?: unknown;
	readonly steps?: readonly Step[];
}
/** The release workflow, read as GitHub reads it. */
const { jobs } = parse(
	readFileSync(
		join(
			import.meta.dirname,
			"..",
			"..",
			"..",
			"..",
			"..",
			"..",
			".github",
			"workflows",
			"release.yml",
		),
		"utf8",
	),
) as { readonly jobs: Record<string, Job> };
const needsOf = (job: Job) => (typeof job.needs === "string" ? [job.needs] : (job.needs ?? []));

it("scans the lists in a job of its own that reads alone, within a time, failing no run", () => {
	const scan = jobs.scan as Job;
	expect(needsOf(scan)).toEqual(["sbom"]);
	expect(scan.permissions).toEqual({ contents: "read" });
	expect(scan["continue-on-error"]).toBe(true);
	expect(typeof scan["timeout-minutes"]).toBe("number");
	const steps = scan.steps ?? [];
	expect(steps.filter((s) => s.run?.includes("pnpm release:scan"))).toHaveLength(1);
	// The lists taken by the id the sbom job gave, never by name.
	const taken = steps.filter((s) => s.uses?.startsWith("actions/download-artifact@"));
	expect(taken.map((s) => s.with?.["artifact-ids"])).toEqual(["${{ needs.sbom.outputs.lists }}"]);
});

it("is needed by no job, so no release waits for it or stops on it", () => {
	const needing = Object.entries(jobs).filter(([, job]) => needsOf(job).includes("scan"));
	expect(needing.map(([name]) => name)).toEqual([]);
});
