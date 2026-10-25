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

/** What a candidate run was found to be: what it tested and how its compliance ended, or why it cannot be read. */
export type Examined =
	| {
			readonly run: RunSeen;
			readonly tested: { readonly commit: string; readonly tree: string };
			readonly compliance: string | undefined;
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

/** Every evidence report's artifact and the compliance table's, the newest of each name; or which is missing or expired. */
export function artifactsOf(
	listed: readonly ArtifactSeen[],
): { readonly take: ArtifactSeen[] } | { readonly problem: string } {
	const newest = new Map<string, ArtifactSeen>();
	for (const a of listed.filter((a) => a.name.startsWith("evidence-") || a.name === "compliance")) {
		const kept = newest.get(a.name);
		if (!kept || a.createdAt > kept.createdAt) newest.set(a.name, a);
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

/** The newest run that tested the tag's tree with its compliance passed; else each candidate's reason, with what to do. */
export function verdictOf(
	tag: Tag,
	examined: readonly Examined[],
):
	| ({ readonly kind: "taken" } & Extract<Examined, { readonly tested: unknown }>)
	| { readonly kind: "stopped"; readonly problems: string[] } {
	if (examined.length === 0) {
		return {
			kind: "stopped",
			problems: [
				`no successful CI run of a pull request to main tested ${tag.head}, the release pull request's head: re-run that pull request's CI, then re-run the failed jobs of this release`,
			],
		};
	}
	const problems: string[] = [];
	for (const e of examined) {
		if ("problem" in e) problems.push(`${e.run.url}: ${e.problem}; ${rerun(e.run)}`);
		else if (e.tested.tree !== tag.tree) {
			problems.push(
				`${e.run.url} tested tree ${e.tested.tree}, but the tag's tree is ${tag.tree}: main moved after it ran, so what it tested is not what the tag publishes; see "When the release finds no evidence" in docs/releasing.md`,
			);
		} else if (e.compliance !== "success") {
			problems.push(
				`${e.run.url}: its compliance job ended ${e.compliance ?? "without running"}; ${rerun(e.run)}`,
			);
		} else return { kind: "taken", ...e };
	}
	return { kind: "stopped", problems };
}
