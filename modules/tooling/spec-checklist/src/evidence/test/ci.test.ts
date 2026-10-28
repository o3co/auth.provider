import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
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

	it("run on a pull request to develop every area and its fault scenes where its files may reach a scene, else none, no pattern, and pass where nothing was planned", () => {
		const plan = job("conformance-plan");
		expect(plan.if).toContain("github.event_name == 'pull_request'");
		expect(plan.if).not.toContain("github.base_ref == 'main'");
		// The change is read against the base, whose history the checkout holds.
		expect(checkout("conformance-plan")?.with?.["fetch-depth"]).toBe(0);
		const step = plan.steps.find((s) => s.id === "plan");
		expect(step?.env).toMatchObject({
			EVENT: expr("github.event_name"),
			BASE: expr("github.base_ref"),
		});
		const lines = (step?.run ?? "").split("\n").map((l) => l.trim());
		for (const line of [
			'if [ "$EVENT" = pull_request ] && [ "$BASE" = develop ]; then',
			`changed=$(git diff --no-renames --name-only "origin/$BASE...HEAD" | jq -Rsc 'split("\\n") | map(select(. != ""))')`,
			'reaches=$(jq -c "$REACHES" <<<"$changed")',
			'if [ "$reaches" != true ]; then',
			"areas='[]'",
			"faults='[]'",
			"patterns='[]'",
		]) {
			expect(lines).toContain(line);
		}
		// The judgement itself, run as the step runs it: by the paths alone, as an area names no module it composes.
		const reaches = (files: readonly string[]) =>
			execFileSync("jq", ["-c", String(step?.env?.REACHES)], {
				input: JSON.stringify(files),
				encoding: "utf8",
			}).trim();
		const cases: readonly (readonly [readonly string[], string])[] = [
			[[], "false"],
			[["docs/compliance/guarantee.md", "docs/audit/cards.md"], "false"],
			[["modules/tooling/spec-checklist/checklist/guarantee.md"], "false"],
			[["modules/tooling/spec-checklist/test/repo.test.ts", "docs/compliance/rfc6749.md"], "false"],
			// The evidence reporter every area's run holds.
			[["modules/tooling/spec-checklist/src/evidence/reporter.ts"], "true"],
			// A module an area composes, which no area names as a dependency.
			[["modules/identity/login-password/src/login.ts"], "true"],
			[["modules/store-redis/redis/src/redis-store.ts"], "true"],
			[["modules/tooling/conformance-device/src/area.ts"], "true"],
			[["modules/tooling/conformance/src/fault-scene/fault-scene.ts"], "true"],
			// Files of no package: the lockfile, the root's settings, the workflows.
			[["pnpm-lock.yaml"], "true"],
			[["package.json"], "true"],
			[[".github/workflows/ci.yml"], "true"],
			[["docs/compliance/guarantee.md", "modules/oauth/code-grant/src/grant.ts"], "true"],
			// A file moved out of a module into the docs: without renames, both its paths are read.
			[["docs/notes/grant.ts", "modules/oauth/code-grant/src/grant.ts"], "true"],
		];
		for (const [files, answer] of cases) expect([files, reaches(files)]).toEqual([files, answer]);
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

	it("read a pull request's moved file by both its paths, in interop-due and the conformance plan", () => {
		const changedLine = (name: string, id: string) =>
			(job(name).steps.find((s) => s.id === id)?.run ?? "")
				.split("\n")
				.map((l) => l.trim())
				.find((l) => l.startsWith("changed=$(git diff")) ?? "";
		expect(changedLine("conformance-plan", "plan")).toContain("--no-renames");
		const line = changedLine("interop-due", "due");
		// A plan moved out of interop-oidf: its old path names what the change touches there.
		const dir = mkdtempSync(join(tmpdir(), "ci-moved-"));
		// git as the scratch repository alone has it: no outer repository a hook names, no user's or
		// system's settings (a global `diff.renames` would change what is read), no hooks.
		const env = {
			...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("GIT_"))),
			GIT_CONFIG_GLOBAL: "/dev/null",
			GIT_CONFIG_NOSYSTEM: "1",
		};
		const git = (...args: string[]) =>
			execFileSync(
				"git",
				[
					"-c",
					"core.hooksPath=/dev/null",
					"-c",
					"user.name=ci",
					"-c",
					"user.email=ci@example.com",
					...args,
				],
				{ cwd: dir, env },
			);
		try {
			git("init", "-q");
			mkdirSync(join(dir, "modules/tooling/interop-oidf/plans"), { recursive: true });
			writeFileSync(join(dir, "modules/tooling/interop-oidf/plans/logout.json"), "{}\n");
			git("add", ".");
			git("commit", "-qm", "base");
			git("branch", "origin/develop");
			mkdirSync(join(dir, "docs"));
			git("mv", "modules/tooling/interop-oidf/plans/logout.json", "docs/logout.json");
			git("commit", "-qm", "moved");
			const read = execFileSync(
				"bash",
				["-c", `set -euo pipefail; ${line}; printf '%s' "$changed"`],
				{
					cwd: dir,
					env: { ...env, BASE: "develop" },
					encoding: "utf8",
				},
			);
			expect(read.split("\n").sort()).toEqual([
				"docs/logout.json",
				"modules/tooling/interop-oidf/plans/logout.json",
			]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
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
