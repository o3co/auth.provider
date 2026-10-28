import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const root = join(import.meta.dirname, "..", "..", "..", "..", "..", "..");

interface Step {
	readonly id?: string;
	readonly name?: string;
	readonly if?: string;
	readonly shell?: string;
	readonly env?: Readonly<Record<string, string>>;
	readonly uses?: string;
	readonly run?: string;
	readonly with?: Readonly<Record<string, unknown>>;
}
interface Job {
	readonly if?: string;
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
		expect(script).toContain("@mod/spec-checklist run plan faults");
		expect(script).toContain('echo "sha=$(git rev-parse HEAD)"');
		expect(plan.outputs?.sha).toBe(expr("steps.plan.outputs.sha"));
		expect(plan.outputs?.faults).toBe(expr("steps.plan.outputs.faults"));
		expect(job("conformance-area").strategy?.matrix?.area).toBe(
			expr("fromJSON(needs.conformance-plan.outputs.areas)"),
		);
		expect(job("conformance-pattern").strategy?.matrix?.pattern).toBe(
			expr("fromJSON(needs.conformance-plan.outputs.patterns)"),
		);
		expect(job("conformance-faults").strategy?.matrix?.area).toBe(
			expr("fromJSON(needs.conformance-plan.outputs.faults)"),
		);
	});

	it("run on a pull request to develop the areas its change reaches and their fault scenes, no pattern, and pass where nothing was planned", () => {
		const plan = job("conformance-plan");
		expect(plan.if).toContain("github.event_name == 'pull_request'");
		expect(plan.if).not.toContain("github.base_ref == 'main'");
		// The change is read against the base, whose history the checkout holds.
		expect(checkout("conformance-plan")?.with?.["fetch-depth"]).toBe(0);
		const step = plan.steps.find((s) => s.id === "plan");
		expect(step?.env).toEqual({ EVENT: expr("github.event_name"), BASE: expr("github.base_ref") });
		const script = step?.run ?? "";
		expect(script).toContain('if [ "$EVENT" = pull_request ] && [ "$BASE" = develop ]; then');
		// The packages the change reaches: those it changed and those depending on them.
		expect(script).toContain(
			`reached=$(pnpm list --recursive --depth -1 --json --filter "...[origin/$BASE]" | jq -c '[.[].name]')`,
		);
		for (const list of ["areas", "faults"]) {
			expect(script).toContain(
				`${list}=$(jq -cn --argjson planned "$${list}" --argjson reached "$reached" '[$planned[] | select(. as $p | $reached | index($p))]')`,
			);
		}
		expect(script).toContain("patterns='[]'");
		// A job with nothing planned is skipped, as a matrix of none cannot run.
		const planned = (list: string) => `needs.conformance-plan.outputs.${list} != '[]'`;
		expect(job("legacy-build").if).toContain(planned("areas"));
		expect(job("conformance-area").if).toContain(planned("areas"));
		expect(job("conformance-faults").if).toContain(planned("faults"));
		expect(job("conformance-pattern").if).toContain(planned("patterns"));
		// The gate runs on every pull request, and takes a job skipped with nothing planned as passed.
		const gate = job("conformance");
		expect(gate.if).toContain("github.event_name == 'pull_request'");
		const check = gate.steps[0];
		expect(check?.env).toMatchObject({
			PLANNED_AREAS: expr("needs.conformance-plan.outputs.areas"),
			PLANNED_PATTERNS: expr("needs.conformance-plan.outputs.patterns"),
			PLANNED_FAULTS: expr("needs.conformance-plan.outputs.faults"),
		});
		expect(check?.run).toContain(
			'if [ "$planned" = "[]" ] && [ "$result" = skipped ]; then continue; fi',
		);
		expect(check?.run).toContain(
			'"legacy-build $PLANNED_AREAS $LEGACY" "conformance-area $PLANNED_AREAS $AREAS" "conformance-pattern $PLANNED_PATTERNS $PATTERNS" "conformance-faults $PLANNED_FAULTS $FAULTS"',
		);
	});

	it("run each area's fault scenes as a fault run, which skips none, and fail conformance where they did not pass", () => {
		const faults = job("conformance-faults");
		const scenes = faults.steps.find((s) => s.name === "Fault scenes");
		expect(scenes?.env?.CONFORMANCE_FAULTS).toBe("1");
		expect(scenes?.run).toContain("run conformance:faults");
		// What a scene ran on is kept apart from the evidence, every file of which compliance reads.
		expect(scenes?.env?.CONFORMANCE_FAULTS_DIR).not.toContain("evidence");
		const gate = jobs.conformance as unknown as {
			needs: readonly string[];
			steps: readonly Step[];
		};
		expect(gate.needs).toContain("conformance-faults");
		expect(gate.steps.map((s) => s.env?.FAULTS)).toContain(expr("needs.conformance-faults.result"));
	});

	it("run conformance's deployment tests that move an instance's clock in one leg of the fault job, failing rather than skipping or matching none, and reporting no evidence", () => {
		const steps = job("conformance-faults").steps;
		const clock = steps.find((s) => s.name === "Deployment tests with a moved clock");
		expect(clock?.if).toBe(expr("!cancelled() && strategy.job-index == 0"));
		expect(clock?.env?.CONFORMANCE_FAULTS).toBe("1");
		// The whole script, so no other config or name filter leaves the clock's tests out unseen, and the
		// count of those that passed, as a filter matching nothing passes with every test skipped.
		const tests = "modules/tooling/conformance/src/deployment/test/deployment.integration.test.ts";
		// The count is the deployment's tests a fault run never skips, those that move a clock.
		const held =
			readFileSync(join(root, tests), "utf8").split("it.runIf(faultRun || hostLibfaketime())(")
				.length - 1;
		expect(held).toBeGreaterThan(0);
		expect(clock?.run).toBe(
			[
				"set -euo pipefail",
				`pnpm exec vitest run --config vitest.integration.config.ts ${tests} -t clock --reporter=default --reporter=json --outputFile.json="$RUNNER_TEMP/clock-tests.json"`,
				`jq -e '.numPassedTests >= ${held}' "$RUNNER_TEMP/clock-tests.json" > /dev/null || {`,
				`  echo "the clock step did not pass the ${held} deployment clock tests it holds" >&2`,
				"  exit 1",
				"}",
				"",
			].join("\n"),
		);
		expect(clock?.shell).toBe("bash");
		expect(clock?.env?.SPEC_EVIDENCE_DIR).toBeUndefined();
		// After the step that takes the library and the one that finds it moves Node's clock.
		const at = (name: string) => steps.findIndex((s) => s.name === name);
		expect(at("Deployment tests with a moved clock")).toBeGreaterThan(
			at("The library moves Node's clock here"),
		);
	});

	it("take the interop matrices from `run plan` in interop-due, which fixes their commit", () => {
		const due = job("interop-due");
		const script = due.steps.find((s) => s.id === "plan")?.run ?? "";
		expect(script).toContain("@mod/spec-checklist run plan oidf-plan");
		expect(script).toContain("@mod/spec-checklist run plan library");
		expect(script).toContain('echo "sha=$(git rev-parse HEAD)"');
		expect(due.outputs?.sha).toBe(expr("steps.plan.outputs.sha"));
		expect(job("interop-oidf").strategy?.matrix?.plan).toBe(
			expr("fromJSON(needs.interop-due.outputs.oidf-plans)"),
		);
		expect(job("interop-clients").strategy?.matrix?.library).toBe(
			expr("fromJSON(needs.interop-due.outputs.libraries)"),
		);
	});

	it("check out the plan's commit in every conformance and interop job and in compliance", () => {
		expect(checkout("conformance-area")?.with?.ref).toBe(
			expr("needs.conformance-plan.outputs.sha"),
		);
		expect(checkout("conformance-pattern")?.with?.ref).toBe(
			expr("needs.conformance-plan.outputs.sha"),
		);
		expect(checkout("conformance-faults")?.with?.ref).toBe(
			expr("needs.conformance-plan.outputs.sha"),
		);
		expect(checkout("interop-oidf")?.with?.ref).toBe(expr("needs.interop-due.outputs.sha"));
		expect(checkout("interop-clients")?.with?.ref).toBe(expr("needs.interop-due.outputs.sha"));
		expect(checkout("compliance")?.with?.ref).toBe(
			expr("needs.conformance-plan.outputs.sha || needs.interop-due.outputs.sha || ''"),
		);
	});

	it("has each job that reports mark its attempt first, keep its evidence by attempt, and a release's compliance fail on a needed job that did not succeed", () => {
		const reporting = {
			checks: "unit",
			integration: "integration",
			"conformance-area": "area",
			"conformance-pattern": "pattern",
			"conformance-faults": "faults",
			"interop-clients": "library",
			"interop-oidf": "oidf-plan",
			"release-check": "release",
		};
		for (const [name, kind] of Object.entries(reporting)) {
			const [first] = job(name).steps;
			expect(first?.name, name).toBe("Mark this attempt");
			expect(first?.env?.KIND, name).toBe(kind);
			const kept = job(name).steps.find(
				(s) => s.name === "Keep the evidence of the tests that ran",
			);
			expect(String(kept?.with?.name), name).toContain(expr("github.run_attempt"));
		}
		const told = job("compliance").steps.find(
			(s) => s.name === "Each item's status from this run's evidence",
		);
		expect(told?.env?.NEEDS).toBe(expr("toJSON(needs)"));
		// Compliance waits for every job that reports, whatever it ended.
		const needs = (jobs.compliance as unknown as { needs: readonly string[] }).needs;
		for (const name of Object.keys(reporting)) expect(needs, name).toContain(name);
		expect(told?.run).toContain('select(.value.result != "success")');
	});
});
