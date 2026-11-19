import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

interface Step {
	readonly uses?: string;
	readonly with?: Record<string, unknown>;
}
interface Job {
	readonly "cache-mode"?: unknown;
	readonly steps?: readonly Step[];
}
interface Workflow {
	readonly "cache-mode"?: unknown;
	readonly jobs?: Record<string, Job>;
}

/** A `ref` that names the event's own commit alone: `github.sha` or `github.ref`. */
const ownCommit = /^\s*\$\{\{\s*github\.(sha|ref)\s*\}\}\s*$/;

/** A checkout's `ref`, its input named in any case, as GitHub reads an input's name. */
const refOf = (s: Step): unknown =>
	Object.entries(s.with ?? {}).find(([name]) => name.toLowerCase() === "ref")?.[1];

/**
 * The jobs of `workflow` that may check out other than their run's own commit (a checkout whose
 * `ref` is written non-empty and names other than `github.sha` or `github.ref` alone, whatever it
 * would evaluate to) and may still write the cache, their `cache-mode`, or the workflow's, being
 * neither `read` nor `none`.
 */
const writingOtherRefs = (workflow: Workflow): string[] =>
	Object.entries(workflow.jobs ?? {})
		.filter(([, job]) =>
			(job.steps ?? []).some((s) => {
				const ref = refOf(s);
				return (
					s.uses?.startsWith("actions/checkout@") === true &&
					ref !== undefined &&
					String(ref).trim() !== "" &&
					!ownCommit.test(String(ref))
				);
			}),
		)
		.filter(
			([, job]) => !["read", "none"].includes(String(job["cache-mode"] ?? workflow["cache-mode"])),
		)
		.map(([name]) => name);

const workflowsDir = join(
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
/** Every workflow of this tree, by file name, read as GitHub reads it. */
const workflows: Record<string, Workflow> = Object.fromEntries(
	readdirSync(workflowsDir)
		.filter((f) => /\.ya?ml$/.test(f))
		.map((f) => [f, parse(readFileSync(join(workflowsDir, f), "utf8")) as Workflow]),
);
/** Each workflow's jobs with their own `cache-mode`, and the workflow's, left out. */
const unset = (workflow: Workflow): Workflow => ({
	jobs: Object.fromEntries(
		Object.entries(workflow.jobs ?? {}).map(([name, { "cache-mode": _, ...job }]) => [name, job]),
	),
});

it("finds nothing in the workflows' directory but workflow files, so none is left unread", () => {
	const entries = readdirSync(workflowsDir, { withFileTypes: true });
	expect(entries.filter((e) => !e.isFile() || !/\.ya?ml$/.test(e.name)).map((e) => e.name)).toEqual(
		[],
	);
});

it("reads every workflow of this tree, CI's among them", () => {
	expect(Object.keys(workflows)).toContain("ci.yml");
	expect(Object.keys(workflows).length).toBeGreaterThan(1);
});

it.each(Object.keys(workflows))(
	"lets no job of %s that may run other than its run's commit write the cache",
	(file) => {
		expect(writingOtherRefs(workflows[file] as Workflow)).toEqual([]);
	},
);

it("finds such jobs across the workflows, so the rule holds something", () => {
	const found = Object.fromEntries(
		Object.entries(workflows).map(([file, w]) => [file, writingOtherRefs(unset(w))]),
	);
	expect(found["ci.yml"]?.length).toBeGreaterThan(0);
	expect(Object.values(found).filter((jobs) => jobs.length > 0).length).toBeGreaterThan(1);
});

const checkout = (ref?: string): Step => ({
	uses: "actions/checkout@0123456789abcdef",
	...(ref === undefined ? {} : { with: { ref } }),
});
it.each<[string, Workflow, string[]]>([
	[
		"a job added later with a computed ref and no cache-mode",
		{ jobs: { later: { steps: [checkout("${{ needs.plan.outputs.sha }}")] } } },
		["later"],
	],
	[
		"a job checking out develop on the schedule, writing",
		{ jobs: { daily: { "cache-mode": "write", steps: [checkout("develop")] } } },
		["daily"],
	],
	[
		"a job saving without restoring",
		{ jobs: { save: { "cache-mode": "write-only", steps: [checkout("refs/tags/v1.0.0")] } } },
		["save"],
	],
	[
		"a job reading or caching nothing, or one the workflow holds to none",
		{
			"cache-mode": "none",
			jobs: {
				reads: { "cache-mode": "read", steps: [checkout("${{ needs.plan.outputs.sha }}")] },
				none: { "cache-mode": "none", steps: [checkout("develop")] },
				held: { steps: [checkout("${{ matrix.ref }}")] },
			},
		},
		[],
	],
	[
		"a job checking out its run's own commit, with no ref or an empty one",
		{ jobs: { own: { steps: [checkout(), checkout("")] } } },
		[],
	],
	[
		"a job whose computed ref is named in another case",
		{
			jobs: {
				upper: {
					steps: [
						{
							uses: "actions/checkout@0123456789abcdef",
							with: { Ref: "${{ needs.plan.outputs.sha }}" },
						},
					],
				},
			},
		},
		["upper"],
	],
	[
		"a job naming the event's own commit, by its sha or its ref",
		{
			jobs: {
				sha: { steps: [checkout("${{ github.sha }}")] },
				ref: { steps: [checkout("${{github.ref}}")] },
			},
		},
		[],
	],
	[
		"a job naming the event's ref beside another",
		{
			jobs: {
				either: {
					steps: [checkout("${{ github.event_name == 'schedule' && 'develop' || github.ref }}")],
				},
			},
		},
		["either"],
	],
])("over %s", (_, workflow, found) => {
	expect(writingOtherRefs(workflow)).toEqual(found);
});
