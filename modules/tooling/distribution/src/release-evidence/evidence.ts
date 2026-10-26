/** Which CI run's evidence a release keeps: the run that tested the tag's tree, or why none will do. */

/** A CI run as the Actions API lists it: what it ran, on which commit, branch and repository, is GitHub's word. */
export interface RunSeen {
	readonly id: number;
	readonly attempt: number;
	readonly conclusion: string | null;
	readonly event: string;
	readonly path: string;
	readonly headSha: string;
	readonly headBranch: string;
	readonly repository: string;
	readonly headRepository: string;
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

/** What a candidate run was found to be: the commit its reports name, how its jobs ended (its latest attempt's, by name), or why it cannot be read. */
export type Examined =
	| {
			readonly run: RunSeen;
			readonly tested: { readonly commit: string };
			readonly jobs: Readonly<Record<string, string | null | undefined>>;
			/** The release's compliance read again over the evidence kept: whether it lets the release go on, and what it told. */
			readonly recomputed: { readonly releasable: boolean; readonly told: string };
			readonly artifacts: readonly ArtifactSeen[];
	  }
	| { readonly run: RunSeen; readonly problem: string };

/** The tag as its checkout holds it, with what restores a cache in its CI workflow in a push to its release branch. */
export interface TagSeen {
	readonly name: string;
	readonly commit: string;
	readonly tree: string;
	readonly parents: readonly string[];
	readonly headTree: string | undefined;
	readonly firstParentOnMain: boolean;
	readonly cacheProblems: readonly string[];
}

/** The tag, once it will do: its commit and tree, the release branch's head CI tested, and that branch. */
export interface Tag {
	readonly commit: string;
	readonly tree: string;
	readonly head: string;
	readonly branch: string;
}

/** The version a tag names: its name without the one `v` it starts with, read as written. */
export const versionOf = (name: string): string | undefined =>
	/^v[^/]+$/.test(name) ? name.slice(1) : undefined;

/**
 * The tag, where it is a release's (a merge of the release branch's head, of its tree, into main, its CI
 * restoring no cache), else each reason it is not. Who may create a release tag is the boundary of review.
 */
export function tagOf(seen: TagSeen): { readonly tag: Tag } | { readonly problems: string[] } {
	const problems: string[] = [];
	const version = versionOf(seen.name);
	if (version === undefined) problems.push(`the tag ${seen.name} names no version (v<version>)`);
	const [first, head, ...more] = seen.parents;
	if (first === undefined || head === undefined || more.length > 0) {
		problems.push(
			`the tag's commit ${seen.commit} has ${seen.parents.length} parents: tag the merge commit of the release branch into main`,
		);
	} else {
		if (seen.headTree !== seen.tree) {
			problems.push(
				`the tag's tree ${seen.tree} is not the tree of ${head}, the release branch's head it merged: main held changes the branch did not, so what CI tested is not what the tag publishes`,
			);
		}
		if (!seen.firstParentOnMain) problems.push(`the tag's first parent ${first} is not on main`);
	}
	for (const p of seen.cacheProblems) problems.push(`the tag's CI workflow ${p}`);
	if (problems.length > 0 || version === undefined || head === undefined) return { problems };
	return { tag: { commit: seen.commit, tree: seen.tree, head, branch: `release/${version}` } };
}

/** CI's successful pushes of the release branch's head (its name as written) in this repository, the newest first. */
export function candidatesOf(runs: readonly RunSeen[], tag: Tag, repository: string): RunSeen[] {
	return runs
		.filter(
			(r) =>
				r.conclusion === "success" &&
				r.event === "push" &&
				r.path === ".github/workflows/ci.yml" &&
				r.headSha === tag.head &&
				r.headBranch === tag.branch &&
				r.repository === repository &&
				r.headRepository === repository,
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

/** The jobs CI runs on a release branch, and must pass there. */
export const releaseJobs = ["conformance", "release-check", "compliance"] as const;

const rerun = (run: RunSeen) =>
	`re-run all jobs of ${run.url}, then re-run the failed jobs of this release`;

/** Why a run examined will not do, with what to do; none where it will. */
function refusalOf(tag: Tag, e: Examined): string | undefined {
	if ("problem" in e) return `${e.run.url}: ${e.problem}; ${rerun(e.run)}`;
	if (e.tested.commit !== tag.head) {
		return `${e.run.url}: its reports name ${e.tested.commit} as tested, but GitHub ran it on ${tag.head}; the reports are not that run's`;
	}
	const unpassed = releaseJobs.filter((job) => e.jobs[job] !== "success");
	if (unpassed.length > 0) {
		const ended = unpassed.map((job) => `its ${job} job ended ${e.jobs[job] ?? "without running"}`);
		return `${e.run.url}: ${ended.join(", ")}: a release branch's run runs and passes ${releaseJobs.join(", ")}; ${rerun(e.run)}`;
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
				`no successful CI run of a push of ${tag.branch} at ${tag.head}, the release branch's head the tag merged: push that branch, or re-run its CI, then re-run the failed jobs of this release`,
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
