/** Which CI run's evidence a release keeps: the run that tested the tag's tree, or why none will do. */

/** A CI run as the Actions API lists it, with the base branches of its pull requests (none, once one is merged). */
export interface RunSeen {
	readonly id: number;
	readonly attempt: number;
	readonly conclusion: string | null;
	readonly event: string;
	readonly headSha: string;
	readonly headBranch: string;
	readonly baseRefs: readonly string[];
	readonly createdAt: string;
	readonly url: string;
}

/** An artifact of a run, as the Actions API lists it. */
export interface ArtifactSeen {
	readonly id: number;
	readonly name: string;
	readonly expired: boolean;
	readonly createdAt: string;
}

/** What a candidate run was found to be: what it tested and how its jobs ended (its latest attempt's, by name), or why it cannot be read. */
export type Examined =
	| {
			readonly run: RunSeen;
			readonly tested: { readonly commit: string; readonly tree: string };
			readonly jobs: Readonly<Record<string, string | null | undefined>>;
			/** The release's compliance read again over the evidence kept: whether it lets the release go on, and what it told. */
			readonly recomputed: { readonly releasable: boolean; readonly told: string };
			readonly artifacts: readonly ArtifactSeen[];
	  }
	| { readonly run: RunSeen; readonly problem: string };

/** The tag: its commit and tree, and the release pull request's head, the merge commit's second parent. */
export interface Tag {
	readonly commit: string;
	readonly tree: string;
	readonly head: string;
}

const rerun = (run: RunSeen) =>
	`re-run all jobs of ${run.url}, then re-run the failed jobs of this release`;

/** The release pull request: its number, and the head and branch it was merged from. */
export interface ReleasePull {
	readonly number: number;
	readonly head: string;
	readonly branch: string;
}

/** The pull request to main that the tag's commit merged, among the pull requests the API lists for that commit. */
export function releasePullOf(
	pulls: readonly {
		readonly number: number;
		readonly mergeCommit: string | null;
		readonly base: string;
		readonly head: string;
		readonly branch: string;
	}[],
	commit: string,
): ReleasePull | undefined {
	const merged = pulls.find((p) => p.mergeCommit === commit && p.base === "main");
	return merged && { number: merged.number, head: merged.head, branch: merged.branch };
}

/** CI's successful runs of the release pull request, from its head and branch, the newest first. */
export function candidatesOf(runs: readonly RunSeen[], pull: ReleasePull): RunSeen[] {
	return runs
		.filter(
			(r) =>
				r.conclusion === "success" &&
				r.event === "pull_request" &&
				r.headSha === pull.head &&
				r.headBranch === pull.branch &&
				(r.baseRefs.length === 0 || r.baseRefs.includes("main")),
		)
		.sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.attempt - a.attempt);
}

/** An evidence artifact's job (its name without the attempt CI ends it with) and that attempt; the compliance table's, by its name alone. */
const keyOf = (a: ArtifactSeen) => {
	const ended = /^(evidence-.+)-(\d+)$/.exec(a.name);
	return ended
		? { job: ended[1] as string, attempt: Number(ended[2]) }
		: { job: a.name, attempt: 0 };
};

/** Each job's evidence from its newest attempt, and the newest compliance table; or which of those is missing or expired, an older attempt's never. */
export function artifactsOf(
	listed: readonly ArtifactSeen[],
): { readonly take: ArtifactSeen[] } | { readonly problem: string } {
	const newest = new Map<string, ArtifactSeen>();
	for (const a of listed.filter((a) => a.name.startsWith("evidence-") || a.name === "compliance")) {
		const { job, attempt } = keyOf(a);
		const kept = newest.get(job);
		const later =
			kept && (attempt - keyOf(kept).attempt || a.createdAt.localeCompare(kept.createdAt));
		if (!kept || (later ?? 0) > 0) newest.set(job, a);
	}
	const take = [...newest.values()].sort((a, b) => a.name.localeCompare(b.name));
	if (!newest.has("compliance")) return { problem: "the run kept no compliance artifact" };
	if (!take.some((a) => a.name.startsWith("evidence-")))
		return { problem: "the run kept no evidence artifact" };
	const expired = take.filter((a) => a.expired).map((a) => a.name);
	if (expired.length > 0) {
		return {
			problem: `${expired.join(", ")} ${expired.length === 1 ? "has" : "have"} expired`,
		};
	}
	return { take };
}

/** The one commit a run's reports name as tested; none where they name none, or more than one. */
export function testedCommitOf(reports: readonly unknown[], run: string): string | undefined {
	const commits = new Set(
		reports.flatMap((r) => {
			const identity = (r as { identity?: { commit?: unknown; run?: unknown } } | null)?.identity;
			return identity?.run === run && typeof identity.commit === "string" ? [identity.commit] : [];
		}),
	);
	return commits.size === 1 ? [...commits][0] : undefined;
}

/** The jobs CI runs on a pull request to main alone, and must pass there: a run that skipped them is no release pull request's. */
export const releaseJobs = ["conformance", "release-check", "compliance"] as const;

/** Why a run examined will not do, with what to do; none where it will. */
function refusalOf(tag: Tag, e: Examined): string | undefined {
	if ("problem" in e) return `${e.run.url}: ${e.problem}; ${rerun(e.run)}`;
	if (e.tested.tree !== tag.tree) {
		return `${e.run.url} tested tree ${e.tested.tree}, but the tag's tree is ${tag.tree}: main moved after it ran, so what it tested is not what the tag publishes; see "When the release finds no evidence" in docs/releasing.md`;
	}
	const unpassed = releaseJobs.filter((job) => e.jobs[job] !== "success");
	if (unpassed.length > 0) {
		const ended = unpassed.map((job) => `its ${job} job ended ${e.jobs[job] ?? "without running"}`);
		return `${e.run.url}: ${ended.join(", ")}: a release pull request's run runs and passes ${releaseJobs.join(", ")}; ${rerun(e.run)}`;
	}
	if (!e.recomputed.releasable) {
		return `${e.run.url}: the evidence it kept no longer makes the release's compliance (${e.recomputed.told}); ${rerun(e.run)}`;
	}
	return undefined;
}

/**
 * Examines the candidates in turn, the newest first, and takes the first that will do, examining no
 * older one; else stops with each candidate's reason, one that could not be examined among them.
 */
export function firstTaken(
	tag: Tag,
	candidates: readonly RunSeen[],
	examine: (run: RunSeen) => Examined,
):
	| ({ readonly kind: "taken" } & Extract<Examined, { readonly tested: unknown }>)
	| { readonly kind: "stopped"; readonly problems: string[] } {
	if (candidates.length === 0) {
		return {
			kind: "stopped",
			problems: [
				`no successful CI run of a pull request to main tested ${tag.head}, the release pull request's head: re-run that pull request's CI, then re-run the failed jobs of this release`,
			],
		};
	}
	const problems: string[] = [];
	for (const run of candidates) {
		let e: Examined;
		try {
			e = examine(run);
		} catch (error) {
			e = {
				run,
				problem: `could not be examined (${error instanceof Error ? error.message : String(error)})`,
			};
		}
		const refused = refusalOf(tag, e);
		if (refused === undefined && "tested" in e) return { kind: "taken", ...e };
		problems.push(refused ?? `${run.url}: could not be judged`);
	}
	return { kind: "stopped", problems };
}
