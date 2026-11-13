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
	readonly permissions?: unknown;
	readonly "timeout-minutes"?: unknown;
	readonly "continue-on-error"?: unknown;
	readonly steps?: readonly Step[];
}
const workflows = join(
	import.meta.dirname,
	"..",
	"..",
	"..",
	"..",
	"..",
	"..",
	".github",
	"workflows",
);
const text = readFileSync(join(workflows, "image-scan.yml"), "utf8");
/** The scan's workflow, read as GitHub reads it. */
const workflow = parse(text) as {
	readonly on: Record<string, unknown>;
	readonly permissions?: unknown;
	readonly jobs: Record<string, Job>;
};
const scan = workflow.jobs["image-scan"] as Job;

it("runs on its daily schedule and a manual run alone, the manual run taking no input", () => {
	expect(Object.keys(workflow.on).toSorted()).toEqual(["schedule", "workflow_dispatch"]);
	expect(workflow.on.workflow_dispatch ?? null).toBeNull();
	expect(Object.keys(workflow.jobs)).toEqual(["image-scan"]);
});

it("scans the commit it runs on, reading alone, with no secret or token, within a time", () => {
	const checkout = (scan.steps ?? []).filter((s) => s.uses?.startsWith("actions/checkout@"));
	expect(checkout).toHaveLength(1);
	expect(checkout[0]?.with).toEqual({ "persist-credentials": false });
	expect(scan.permissions).toEqual({ contents: "read" });
	expect(workflow.permissions).toEqual({ contents: "read" });
	expect(text).not.toMatch(/secrets\.|github\.token|GITHUB_TOKEN/);
	expect(typeof scan["timeout-minutes"]).toBe("number");
	expect(scan["continue-on-error"]).toBeUndefined();
});

it("packs the release, scans its app's image, and keeps what it found however the scan ended", () => {
	const steps = scan.steps ?? [];
	const at = (command: string) => steps.findIndex((s) => s.run?.includes(command));
	const pack = steps[at("pnpm bundles")]?.run ?? "";
	expect(pack.indexOf(".github/scripts/pack-published.sh")).toBeGreaterThan(
		pack.indexOf("pnpm bundles"),
	);
	expect(at("pnpm image:scan")).toBeGreaterThan(at("pnpm bundles"));
	const summary = steps.findIndex((s) => s.run?.includes("$GITHUB_STEP_SUMMARY"));
	expect(summary).toBeGreaterThan(at("pnpm image:scan"));
	expect(steps[summary]?.if).toBe("always()");
	const kept = steps.filter((s) => s.uses?.startsWith("actions/upload-artifact@"));
	expect(kept).toHaveLength(1);
	expect(kept[0]?.if).toBe("always()");
	expect(String(kept[0]?.with?.path)).toMatch(/image\.trivy\.json$/);
	expect(kept[0]?.with?.["retention-days"]).toBe(7);
});
