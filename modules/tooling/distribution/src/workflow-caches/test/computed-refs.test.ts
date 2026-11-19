import { readFileSync } from "node:fs";
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
	readonly jobs: Record<string, Job>;
}

/** A `ref` that names the event's own commit alone: `github.sha` or `github.ref`. */
const ownCommit = /^\s*\$\{\{\s*github\.(sha|ref)\s*\}\}\s*$/;

/**
 * The jobs of `workflow` that may check out other than their run's own commit (a checkout whose
 * `ref` is written non-empty and names other than `github.sha` or `github.ref` alone, whatever it
 * would evaluate to) and may still write the cache, their `cache-mode`, or the workflow's, being
 * neither `read` nor `none`.
 */
const writingOtherRefs = (workflow: Workflow): string[] =>
	Object.entries(workflow.jobs)
		.filter(([, job]) =>
			(job.steps ?? []).some(
				(s) =>
					s.uses?.startsWith("actions/checkout@") &&
					s.with?.ref !== undefined &&
					String(s.with.ref).trim() !== "" &&
					!ownCommit.test(String(s.with.ref)),
			),
		)
		.filter(
			([, job]) => !["read", "none"].includes(String(job["cache-mode"] ?? workflow["cache-mode"])),
		)
		.map(([name]) => name);

const ci = parse(
	readFileSync(
		join(import.meta.dirname, "..", "..", "..", "..", "..", "..", ".github", "workflows", "ci.yml"),
		"utf8",
	),
) as Workflow;

it("lets no job of CI's workflow that runs a ref other than its run's commit write the cache", () => {
	expect(writingOtherRefs(ci)).toEqual([]);
});

it("finds such jobs in CI's workflow, so the rule holds something", () => {
	const unset: Workflow = {
		jobs: Object.fromEntries(
			Object.entries(ci.jobs).map(([name, { "cache-mode": _, ...job }]) => [name, job]),
		),
	};
	expect(writingOtherRefs(unset).length).toBeGreaterThan(0);
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
