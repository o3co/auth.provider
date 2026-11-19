import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

type Job = Record<string, unknown> & { readonly steps?: readonly Record<string, unknown>[] };
interface Workflow {
	readonly on: Record<string, unknown>;
	readonly env?: unknown;
	readonly defaults?: unknown;
	readonly permissions?: unknown;
	readonly concurrency?: unknown;
	readonly jobs: Record<string, Job>;
}
const workflow = parse(
	readFileSync(
		join(import.meta.dirname, "..", "..", "..", "..", "..", "..", ".github", "workflows", "ci.yml"),
		"utf8",
	),
) as Workflow;

/**
 * The `audit` job as it must be, every key of it and of its steps, in order: install, pack the
 * release, audit its app's install. A difference fails; change this object on purpose, with the
 * job, when the job is meant to change. Only what upkeep changes is set aside: an action's version,
 * a step's name, and blank and comment lines of a command.
 */
const canonical = {
	if: "github.event_name != 'pull_request'",
	"runs-on": "ubuntu-latest",
	steps: [
		{ uses: "actions/checkout" },
		{ uses: "pnpm/action-setup" },
		{ uses: "actions/setup-node", with: { "node-version": "24" } },
		{ run: ["pnpm install --frozen-lockfile"] },
		{
			run: [
				"set -euo pipefail",
				"pnpm bundles",
				'.github/scripts/pack-published.sh "$RUNNER_TEMP/tarballs"',
			],
		},
		{ run: ['pnpm app:audit "$RUNNER_TEMP/tarballs"'] },
	],
};

/** The job with what upkeep changes set aside. */
const normal = (job: Job) => ({
	...job,
	steps: (job.steps ?? []).map(({ name: _, ...step }) => ({
		...step,
		...(typeof step.uses === "string" ? { uses: step.uses.replace(/@.*$/, "") } : {}),
		...(typeof step.run === "string"
			? {
					run: step.run
						.split("\n")
						.map((line) => line.trim())
						.filter((line) => line !== "" && !line.startsWith("#")),
				}
			: {}),
	})),
});

/**
 * What of the workflow, shared with its other jobs, the audit needs as it is: when it runs, daily
 * and on every push to develop, main and a release branch, and by hand; and nothing that cancels
 * it, widens what it may do, or sets its environment or shell. A change to the workflow's triggers
 * changes this object on purpose.
 */
const concurrencyGroup =
	// biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub expression, not a template
	"ci-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || github.run_id }}";
const canonicalWorkflow = {
	schedule: [{ cron: "17 3 * * *" }],
	push: { branches: ["develop", "main", "release/**"] },
	dispatch: true,
	permissions: { contents: "read" },
	concurrency: {
		group: concurrencyGroup,
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub expression, not a template
		"cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
	},
	env: undefined,
	defaults: undefined,
};
const workflowPart = (w: Workflow) => ({
	schedule: w.on.schedule,
	push: w.on.push,
	dispatch: "workflow_dispatch" in w.on,
	permissions: w.permissions,
	concurrency: w.concurrency,
	env: w.env,
	defaults: w.defaults,
});
const workflowHeld = (w: Workflow) =>
	expect(workflowPart(w), "update the canonical workflow on purpose").toStrictEqual(
		canonicalWorkflow,
	);

const audit = workflow.jobs.audit as Job;
const steps = audit.steps ?? [];
const held = (job: Job) =>
	expect(normal(job), "update the canonical job on purpose").toEqual(canonical);

it("is the canonical job: install, pack the release, audit its app's install", () => {
	held(audit);
});

it("runs daily, on every push to develop, main and a release branch, and by hand, uncancelled", () => {
	workflowHeld(workflow);
});

const auditStep = steps.length - 1;
const withStep = (at: number, extra: Record<string, unknown>): Job => ({
	...audit,
	steps: steps.map((s, i) => (i === at ? { ...s, ...extra } : s)),
});
it.each<[string, Job]>([
	["with the audit step allowed to fail", withStep(auditStep, { "continue-on-error": true })],
	["with the job allowed to fail", { ...audit, "continue-on-error": true }],
	["with the audit step skipped", withStep(auditStep, { if: "false" })],
	["with the job skipped", { ...audit, if: "false" }],
	[
		"with an environment on the audit step",
		withStep(auditStep, { env: { NODE_OPTIONS: "-e process.exit(0)" } }),
	],
	["checking out another ref", withStep(0, { with: { ref: "main" } })],
	[
		"with the setup actions after the commands",
		{ ...audit, steps: [...steps.slice(3), ...steps.slice(0, 3)] },
	],
	[
		"without the install and the bundles",
		{ ...audit, steps: steps.filter((s) => !/pnpm (install|bundles)/.test(String(s.run ?? ""))) },
	],
	[
		"with an audit of its own",
		{ ...audit, steps: [...steps, { run: "pnpm audit --prod --audit-level=low" }] },
	],
	[
		"with a filtered audit",
		{ ...audit, steps: [...steps, { run: "pnpm --filter @mod/conformance audit --prod" }] },
	],
	[
		"with packages dropped from the lockfile",
		{ ...audit, steps: [...steps, { run: "pnpm remove vitest picomatch" }] },
	],
	[
		"with an action of another's",
		{ ...audit, steps: [...steps, { uses: "someone/audit-action@v1" }] },
	],
])("refuses the job %s", (_, mutated) => {
	expect(() => held(mutated)).toThrow();
});

const withOn = (on: Record<string, unknown>): Workflow => ({
	...workflow,
	on: { ...workflow.on, ...on },
});
const { workflow_dispatch: _, ...undispatched } = workflow.on;
const push = workflow.on.push as { readonly branches: readonly string[] };
it.each<[string, Workflow]>([
	["run yearly", withOn({ schedule: [{ cron: "17 3 1 1 *" }] })],
	["without its schedule", withOn({ schedule: undefined })],
	[
		"with its branches negated",
		withOn({ push: { branches: [...push.branches, "!develop", "!main", "!release/**"] } }),
	],
	["with push paths", withOn({ push: { ...push, paths: ["docs/**"] } })],
	["with push paths ignored", withOn({ push: { ...push, "paths-ignore": ["**"] } })],
	["with push branches ignored", withOn({ push: { ...push, "branches-ignore": ["develop"] } })],
	["without its manual run", { ...workflow, on: undispatched }],
	[
		"cancelling a run in progress",
		{ ...workflow, concurrency: { group: "ci", "cancel-in-progress": true } },
	],
	["with every permission", { ...workflow, permissions: "write-all" }],
	["with an environment", { ...workflow, env: { NODE_OPTIONS: "-e process.exit(0)" } }],
	["with a shell of its own", { ...workflow, defaults: { run: { shell: "sh -c true" } } }],
])("refuses the workflow %s", (_, mutated) => {
	expect(() => workflowHeld(mutated)).toThrow();
});

it("takes an action's new version, a step's new name and a comment in a command", () => {
	held({
		...audit,
		steps: steps.map((s, i) => ({
			...s,
			...(typeof s.uses === "string" ? { uses: s.uses.replace(/@.*$/, "@0123456789abcdef") } : {}),
			...(i === auditStep ? { name: "Audit", run: `# the app's install\n${String(s.run)}\n` } : {}),
		})),
	});
});
