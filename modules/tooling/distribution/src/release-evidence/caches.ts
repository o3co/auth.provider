/**
 * Whether a workflow could restore a cache, saved by whoever, in a run a release takes evidence from.
 * Nothing is evaluated: a step that could must be written exactly as set out here, or it is refused.
 */
import { parse } from "yaml";

/** The runs a release may take evidence from: a push to a release branch, and a pull request to main. */
export const evidenceRun =
	"(github.event_name == 'push' && startsWith(github.ref, 'refs/heads/release/')) || (github.event_name == 'pull_request' && github.base_ref == 'main')";

/** The one `if:` a step that restores a cache may carry, and the one `cache:` of an action caching by default. */
export const offInEvidence = `\${{ !(${evidenceRun}) }}`;

/** The one `cache:` setup-java may name maven by. */
export const mavenOffInEvidence = `\${{ !(${evidenceRun}) && 'maven' || '' }}`;

interface Step {
	readonly name?: string;
	readonly uses?: string;
	readonly if?: unknown;
	readonly with?: Readonly<Record<string, unknown>>;
}

interface Job {
	readonly uses?: string;
	readonly steps?: readonly Step[];
}

/** Where a workflow runs: CI, which may turn a cache off in the runs a release takes evidence from, or the release, which restores none at all. */
export type Runs = "ci" | "release";

type Rule = (inputs: Readonly<Record<string, unknown>>, step: Step, runs: Runs) => string[];

const written = (inputs: Readonly<Record<string, unknown>>, input: string) =>
	Object.hasOwn(inputs, input);
const off = (v: unknown) => v === false || v === "false";

/** A step that restores a cache whenever it runs. */
const restores: Rule = (_, step, runs) =>
	runs === "ci" && step.if === offInEvidence
		? []
		: [
				runs === "ci"
					? `it restores a cache: its if: must be ${offInEvidence}`
					: "it restores a cache, which the release never does",
			];

/** An input left out, or written as one of the values given. */
const onlyAs =
	(input: string, taken: readonly unknown[], inCi: readonly unknown[] = []): Rule =>
	(inputs, _, runs) =>
		!written(inputs, input) || [...taken, ...(runs === "ci" ? inCi : [])].includes(inputs[input])
			? []
			: [
					`its ${input} must be left out or written as ${[...taken, ...(runs === "ci" ? inCi : [])].map((t) => JSON.stringify(t)).join(" or ")}`,
				];

const absent =
	(...names: string[]): Rule =>
	(inputs) =>
		names
			.filter((n) => written(inputs, n))
			.map((n) => `it names ${n}, which reaches past this run`);

/** The actions a workflow may use, by name, each with the refs it may be used at and how its cache must be written. */
const known: Readonly<
	Record<string, { readonly refs: readonly string[]; readonly rules: readonly Rule[] }>
> = {
	"actions/checkout": { refs: ["v4"], rules: [] },
	"actions/upload-artifact": { refs: ["v4"], rules: [] },
	"actions/download-artifact": { refs: ["v4"], rules: [absent("run-id", "github-token")] },
	"actions/cache": { refs: ["v4"], rules: [restores] },
	"actions/cache/restore": { refs: ["v4"], rules: [restores] },
	// v5 and later cache on their own (package-manager-cache): not taken.
	"actions/setup-node": { refs: ["v4"], rules: [onlyAs("cache", [""])] },
	"actions/setup-python": { refs: ["v5"], rules: [onlyAs("cache", [""])] },
	"actions/setup-java": { refs: ["v4"], rules: [onlyAs("cache", [""], [mavenOffInEvidence])] },
	// Its cache is on unless written off.
	"actions/setup-go": {
		refs: ["v5"],
		rules: [
			(inputs, _, runs) =>
				written(inputs, "cache") &&
				(off(inputs.cache) || (runs === "ci" && inputs.cache === offInEvidence))
					? []
					: [
							runs === "ci"
								? `its cache is on unless written as false or ${offInEvidence}`
								: "its cache is on unless written as false, as the release restores none",
						],
		],
	},
	"pnpm/action-setup": {
		refs: ["v4", "b906affcce14559ad1aafd4ab0e942779e9f58b1"],
		rules: [onlyAs("cache", [false, "false"]), onlyAs("run_install", [false, "false"])],
	},
	"softprops/action-gh-release": {
		refs: ["3bb12739c298aeb8a4eeaf626c5b8d85266b0e65"],
		rules: [],
	},
};

/** Each problem in the workflow at `path` (from the repository's root) and the workflows of this tree it calls. */
export function cacheProblems(
	path: string,
	readFile: (path: string) => string,
	runs: Runs,
	calling: readonly string[] = [],
): string[] {
	if (calling.includes(path)) {
		return [`${[...calling, path].join(" → ")}: the workflows call each other in a loop`];
	}
	const workflow = parse(readFile(path)) as { readonly jobs?: Readonly<Record<string, Job>> };
	const problems: string[] = [];
	for (const [id, job] of Object.entries(workflow.jobs ?? {})) {
		const where = `${path}: job ${id}`;
		if (job.uses !== undefined) {
			if (!job.uses.startsWith("./.github/workflows/")) {
				problems.push(`${where} calls ${job.uses}, a workflow outside this tree`);
			} else {
				problems.push(...cacheProblems(job.uses.slice(2), readFile, runs, [...calling, path]));
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
			// GitHub reads an input's name without regard to case.
			const inputs: Record<string, unknown> = {};
			for (const [name, value] of Object.entries(step.with ?? {})) {
				if (Object.hasOwn(inputs, name.toLowerCase())) problems.push(`${at} names ${name} twice`);
				inputs[name.toLowerCase()] = value;
			}
			for (const rule of action.rules) {
				for (const problem of rule(inputs, step, runs)) problems.push(`${at}: ${problem}`);
			}
		}
	}
	return problems;
}
