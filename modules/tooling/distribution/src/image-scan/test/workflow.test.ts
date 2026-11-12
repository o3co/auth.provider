import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

interface Step {
	readonly run?: string;
	readonly uses?: string;
	readonly if?: string;
	readonly with?: Record<string, unknown>;
}
interface Job {
	readonly if?: string;
	readonly needs?: string | readonly string[];
	readonly permissions?: unknown;
	readonly "timeout-minutes"?: unknown;
	readonly "continue-on-error"?: unknown;
	readonly steps?: readonly Step[];
}
/** CI's workflow, read as GitHub reads it. */
const ci = parse(
	readFileSync(
		join(import.meta.dirname, "..", "..", "..", "..", "..", "..", ".github", "workflows", "ci.yml"),
		"utf8",
	),
) as {
	readonly on: {
		readonly workflow_dispatch?: { inputs?: Record<string, Record<string, unknown>> };
	};
	readonly permissions?: unknown;
	readonly jobs: Record<string, Job>;
};
const scan = ci.jobs["image-scan"] as Job;
const needsOf = (job: Job) => (typeof job.needs === "string" ? [job.needs] : (job.needs ?? []));

it("runs on the daily schedule and a manual run alone, never on a push or a pull request", () => {
	expect(scan.if).toBe(
		"github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
	);
});

it("scans main, or the ref a manual run names, reading alone, within a time", () => {
	const ref = ci.on.workflow_dispatch?.inputs?.ref;
	expect(ref?.required).toBe(false);
	expect(ref?.default).toBe("main");
	const checkout = (scan.steps ?? []).filter((s) => s.uses?.startsWith("actions/checkout@"));
	expect(checkout).toHaveLength(1);
	expect(checkout[0]?.with?.ref).toBe("${{ inputs.ref || 'main' }}");
	expect(checkout[0]?.with?.["persist-credentials"]).toBe(false);
	expect(scan.permissions).toBeUndefined();
	expect(ci.permissions).toEqual({ contents: "read" });
	expect(typeof scan["timeout-minutes"]).toBe("number");
	expect(scan["continue-on-error"]).toBeUndefined();
});

it("packs the release, scans its app's image, and writes what it found to the summary however the scan ended", () => {
	const steps = scan.steps ?? [];
	const at = (text: string) => steps.findIndex((s) => s.run?.includes(text));
	const pack = steps[at("pnpm bundles")]?.run ?? "";
	expect(pack.indexOf(".github/scripts/pack-published.sh")).toBeGreaterThan(
		pack.indexOf("pnpm bundles"),
	);
	expect(at("pnpm image:scan")).toBeGreaterThan(at("pnpm bundles"));
	const summary = steps.findIndex((s) => s.run?.includes("$GITHUB_STEP_SUMMARY"));
	expect(summary).toBeGreaterThan(at("pnpm image:scan"));
	expect(steps[summary]?.if).toBe("always()");
});

it("is needed by no job, so no other check waits for it", () => {
	const needing = Object.entries(ci.jobs).filter(([, job]) => needsOf(job).includes("image-scan"));
	expect(needing.map(([name]) => name)).toEqual([]);
});
