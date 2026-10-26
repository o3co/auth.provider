/**
 * Whether a workflow, in a run whose evidence a release may take, restores any cache: a cache is
 * whatever an earlier run saved, and who that was is not known. Every action a workflow uses must be
 * one this check knows, with the inputs that turn its cache on read as GitHub reads them, defaults
 * included; a workflow of this tree it calls is read the same way.
 */
import { parse } from "yaml";
import {
	conditionOf,
	inputOf,
	isUnknown,
	type RunContext,
	truthy,
	type Unknown,
	type Value,
} from "./expression.ts";

export type { RunContext } from "./expression.ts";

/** The runs whose evidence a release may take, for its version: a push to its release branch, and a pull request to main. */
export const evidenceRuns = (version: string): RunContext[] => [
	{ event_name: "push", ref: `refs/heads/release/${version}`, base_ref: "" },
	{ event_name: "pull_request", ref: "refs/pull/1/merge", base_ref: "main" },
];

/** The release's own run, for its version: a push of its tag. */
export const releaseRun = (version: string): RunContext => ({
	event_name: "push",
	ref: `refs/tags/v${version}`,
	base_ref: "",
});

interface Step {
	readonly name?: string;
	readonly uses?: string;
	readonly if?: unknown;
	readonly with?: Readonly<Record<string, unknown>>;
}

interface Job {
	readonly if?: unknown;
	readonly uses?: string;
	readonly steps?: readonly Step[];
}

type Rule = (
	inputs: Readonly<Record<string, unknown>>,
	context: RunContext,
	step: Step,
) => string[];

/** An input that must read as false, its default when it is not written. */
const off =
	(input: string, byDefault: boolean): Rule =>
	(inputs, context) => {
		const v: Value | Unknown = Object.hasOwn(inputs, input)
			? inputOf(inputs[input], context)
			: byDefault;
		if (isUnknown(v)) return [`its ${input} cannot be read (${v.unknown})`];
		return String(v).toLowerCase() === "false" || v === false ? [] : [`its ${input} is on`];
	};

/** An input that must be empty, as it is when it is not written. */
const empty =
	(input: string): Rule =>
	(inputs, context) => {
		if (!Object.hasOwn(inputs, input)) return [];
		const v = inputOf(inputs[input], context);
		if (isUnknown(v)) return [`its ${input} cannot be read (${v.unknown})`];
		return v === "" || v === null ? [] : [`its ${input} is ${JSON.stringify(v)}`];
	};

const absent =
	(...names: string[]): Rule =>
	(inputs) =>
		names
			.filter((n) => Object.hasOwn(inputs, n))
			.map((n) => `it names ${n}, which reaches past this run`);

/** The actions a workflow may use, by name, each with the refs it may be used at and what turns its cache on. */
const known: Readonly<
	Record<string, { readonly refs: readonly string[]; readonly rules: readonly Rule[] }>
> = {
	"actions/checkout": { refs: ["v4"], rules: [] },
	"actions/upload-artifact": { refs: ["v4"], rules: [] },
	"actions/download-artifact": { refs: ["v4"], rules: [absent("run-id", "github-token")] },
	"actions/cache": { refs: ["v4"], rules: [() => ["it restores a cache"]] },
	"actions/cache/restore": { refs: ["v4"], rules: [() => ["it restores a cache"]] },
	// v5 and later cache on their own (package-manager-cache): not taken.
	"actions/setup-node": { refs: ["v4"], rules: [empty("cache")] },
	"actions/setup-java": { refs: ["v4"], rules: [empty("cache")] },
	"actions/setup-go": { refs: ["v5"], rules: [off("cache", true)] },
	"pnpm/action-setup": {
		refs: ["v4", "b906affcce14559ad1aafd4ab0e942779e9f58b1"],
		rules: [off("cache", false), off("run_install", false)],
	},
	"softprops/action-gh-release": { refs: ["3bb12739c298aeb8a4eeaf626c5b8d85266b0e65"], rules: [] },
};

/** Whether a job or step may run in the context: only one decided false never runs. */
const mayRun = (written: unknown, context: RunContext): boolean => {
	if (written === undefined) return true;
	const v = conditionOf(written, context);
	return isUnknown(v) || truthy(v);
};

/**
 * Each problem in the workflow at `path` (a path from the repository's root) and the workflows of this
 * tree it calls, for a run of the context given: an action it does not know or at a ref not taken, a
 * cache that could be restored, a call it cannot follow. None where the run restores no cache.
 */
export function cacheProblems(
	path: string,
	context: RunContext,
	readFile: (path: string) => string,
	calling: readonly string[] = [],
): string[] {
	if (calling.includes(path))
		return [`${[...calling, path].join(" → ")}: the workflows call each other in a loop`];
	const workflow = parse(readFile(path)) as { readonly jobs?: Readonly<Record<string, Job>> };
	const problems: string[] = [];
	for (const [id, job] of Object.entries(workflow.jobs ?? {})) {
		const where = `${path}: job ${id}`;
		const runs = mayRun(job.if, context);
		if (job.uses !== undefined) {
			if (!job.uses.startsWith("./.github/workflows/")) {
				problems.push(`${where} calls ${job.uses}, a workflow outside this tree`);
			} else if (runs) {
				problems.push(...cacheProblems(job.uses.slice(2), context, readFile, [...calling, path]));
			}
			continue;
		}
		for (const step of job.steps ?? []) {
			if (step.uses === undefined) continue;
			const at = `${where}, step ${JSON.stringify(step.name ?? step.uses)}`;
			const m = /^([^@./][^@]*)@([^@]+)$/.exec(step.uses);
			const action = m && Object.hasOwn(known, m[1] as string) ? known[m[1] as string] : undefined;
			if (!m || action === undefined) {
				problems.push(`${at} uses ${step.uses}, an action this check does not know`);
				continue;
			}
			if (!action.refs.includes(m[2] as string)) {
				problems.push(`${at} uses ${m[1]} at ${m[2]}, a ref not taken (${action.refs.join(", ")})`);
				continue;
			}
			if (!runs || !mayRun(step.if, context)) continue;
			// GitHub reads an input's name without regard to case.
			const inputs: Record<string, unknown> = {};
			for (const [name, value] of Object.entries(step.with ?? {})) {
				if (Object.hasOwn(inputs, name.toLowerCase())) problems.push(`${at} names ${name} twice`);
				inputs[name.toLowerCase()] = value;
			}
			for (const rule of action.rules) {
				for (const problem of rule(inputs, context, step)) {
					problems.push(`${at}: ${problem} in a ${context.event_name} of ${context.ref}`);
				}
			}
		}
	}
	return problems;
}
