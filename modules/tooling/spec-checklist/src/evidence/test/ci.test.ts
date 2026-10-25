import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const root = join(import.meta.dirname, "..", "..", "..", "..", "..", "..");

interface Step {
	readonly id?: string;
	readonly uses?: string;
	readonly run?: string;
	readonly with?: Readonly<Record<string, unknown>>;
}
interface Job {
	readonly outputs?: Readonly<Record<string, string>>;
	readonly strategy?: { readonly matrix?: Readonly<Record<string, unknown>> };
	readonly steps: readonly Step[];
}

const jobs = (
	parse(readFileSync(join(root, ".github", "workflows", "ci.yml"), "utf8")) as {
		jobs: Readonly<Record<string, Job>>;
	}
).jobs;
const job = (name: string): Job => {
	const found = jobs[name];
	if (!found) throw new Error(`ci.yml has no job ${name}`);
	return found;
};
/** A workflow expression, `${{ … }}` as written. */
const expr = (inner: string) => `$${"{{"} ${inner} }}`;
const checkout = (name: string) =>
	job(name).steps.find((s) => s.uses?.startsWith("actions/checkout"));

describe("CI's jobs, as spec-checklist's runs plan them", () => {
	it("take the area and pattern matrices from `run plan`, and the plan fixes its commit", () => {
		const plan = job("conformance-plan");
		const script = plan.steps.find((s) => s.id === "plan")?.run ?? "";
		expect(script).toContain("@mod/spec-checklist run plan area");
		expect(script).toContain("@mod/spec-checklist run plan pattern");
		expect(script).toContain('echo "sha=$(git rev-parse HEAD)"');
		expect(plan.outputs?.sha).toBe(expr("steps.plan.outputs.sha"));
		expect(job("conformance-area").strategy?.matrix?.area).toBe(
			expr("fromJSON(needs.conformance-plan.outputs.areas)"),
		);
		expect(job("conformance-pattern").strategy?.matrix?.pattern).toBe(
			expr("fromJSON(needs.conformance-plan.outputs.patterns)"),
		);
	});

	it("check out the plan's commit in every conformance job and in compliance", () => {
		expect(checkout("conformance-area")?.with?.ref).toBe(
			expr("needs.conformance-plan.outputs.sha"),
		);
		expect(checkout("conformance-pattern")?.with?.ref).toBe(
			expr("needs.conformance-plan.outputs.sha"),
		);
		expect(checkout("compliance")?.with?.ref).toBe(
			expr("needs.conformance-plan.outputs.sha || ''"),
		);
	});
});
