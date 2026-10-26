import { describe, expect, it } from "vitest";
import {
	type ArtifactSeen,
	artifactsOf,
	candidatesOf,
	type Examined,
	firstTaken,
	type RunSeen,
	type TagSeen,
	tagOf,
	testedCommitOf,
	versionOf,
} from "../evidence.ts";

const head = "h".repeat(40);
const repository = "o3co/auth.provider";
const tag = { commit: "c".repeat(40), tree: "t".repeat(40), head, branch: "release/1.0.1" };
const run = (over: Partial<RunSeen>): RunSeen => ({
	id: 1,
	attempt: 1,
	conclusion: "success",
	event: "push",
	path: ".github/workflows/ci.yml",
	headSha: head,
	headBranch: "release/1.0.1",
	repository,
	headRepository: repository,
	createdAt: "2026-10-26T01:00:00Z",
	url: "https://github.example/runs/1",
	...over,
});
const artifact = (name: string, over: Partial<ArtifactSeen> = {}): ArtifactSeen => ({
	id: name.length,
	name,
	expired: false,
	createdAt: "2026-10-26T01:00:00Z",
	...over,
});

describe("the tag a release may publish", () => {
	const seen = (over: Partial<TagSeen> = {}): TagSeen => ({
		name: "v1.0.1",
		commit: tag.commit,
		tree: tag.tree,
		parents: ["m".repeat(40), head],
		headTree: tag.tree,
		firstParentOnMain: true,
		cacheProblems: [],
		...over,
	});

	it("is a merge of the release branch's head into main, of that head's tree, naming the branch by its version as written", () => {
		expect(tagOf(seen())).toEqual({ tag });
		expect(versionOf("v1.0.1")).toBe("1.0.1");
		expect(versionOf("1.0.1")).toBeUndefined();
	});

	it("is no commit of one parent or of three", () => {
		expect(tagOf(seen({ parents: [head] }))).toEqual({
			problems: [expect.stringMatching(/has 1 parents: tag the merge commit/)],
		});
		expect(tagOf(seen({ parents: ["a", "b", "c"] }))).toEqual({
			problems: [expect.stringMatching(/has 3 parents/)],
		});
	});

	it("is no merge whose tree differs from the head CI tested, nor one whose first parent is not on main", () => {
		expect(tagOf(seen({ headTree: "o".repeat(40) }))).toEqual({
			problems: [expect.stringMatching(/main held changes the branch did not/)],
		});
		expect(tagOf(seen({ firstParentOnMain: false }))).toEqual({
			problems: [expect.stringMatching(/first parent .* is not on main/)],
		});
	});

	it("is none whose CI workflow would restore a cache in a push of its release branch", () => {
		expect(tagOf(seen({ cacheProblems: ["job a: it restores a cache"] }))).toEqual({
			problems: ["the tag's CI workflow job a: it restores a cache"],
		});
	});

	it("is none whose name is no version", () => {
		expect(tagOf(seen({ name: "release-1" }))).toEqual({
			problems: [expect.stringMatching(/names no version/)],
		});
	});
});

describe("the runs that may hold a release's evidence", () => {
	it("are CI's successful pushes of the release branch's head, in this repository, as GitHub states them, the newest first", () => {
		const older = run({ id: 1, createdAt: "2026-10-25T01:00:00Z" });
		const newer = run({ id: 2, attempt: 2, createdAt: "2026-10-26T01:00:00Z" });
		const found = candidatesOf(
			[
				older,
				newer,
				run({ id: 3, conclusion: "failure" }),
				run({ id: 4, event: "pull_request" }),
				run({ id: 5, event: "workflow_dispatch" }),
				run({ id: 6, headSha: "x".repeat(40) }),
				run({ id: 7, headBranch: "develop" }),
				// A branch that names the version otherwise is not the tag's, though semver reads it alike.
				run({ id: 8, headBranch: "release/1.0.01" }),
				run({ id: 9, path: ".github/workflows/other.yml" }),
				run({ id: 10, headRepository: "someone/fork" }),
				// Each repository field on its own, so neither check stands in for the other.
				run({ id: 11, repository: "someone/else" }),
			],
			tag,
			repository,
		);
		expect(found.map((r) => r.id)).toEqual([2, 1]);
	});
});

describe("the artifacts a run's evidence is taken from", () => {
	it("takes every evidence report's and the compliance table's, the newest of each name", () => {
		const listed = [
			artifact("evidence-checks-24-1"),
			artifact("evidence-area-0-1"),
			artifact("compliance", { id: 10, createdAt: "2026-10-26T01:00:00Z" }),
			artifact("compliance", { id: 11, createdAt: "2026-10-26T02:00:00Z" }),
			artifact("conformance-output-full"),
			artifact("legacy-build"),
		];
		expect(artifactsOf(listed)).toEqual({
			take: [
				artifact("compliance", { id: 11, createdAt: "2026-10-26T02:00:00Z" }),
				artifact("evidence-area-0-1"),
				artifact("evidence-checks-24-1"),
			],
		});
	});

	it("takes each job's newest attempt, an older attempt's expiry stopping nothing", () => {
		const listed = [
			artifact("evidence-area-0-1", { id: 1, expired: true }),
			artifact("evidence-area-0-2", { id: 2 }),
			artifact("evidence-checks-24-1", { id: 3 }),
			artifact("compliance", { id: 4 }),
		];
		expect(artifactsOf(listed)).toEqual({
			take: [
				artifact("compliance", { id: 4 }),
				artifact("evidence-area-0-2", { id: 2 }),
				artifact("evidence-checks-24-1", { id: 3 }),
			],
		});
		expect(
			artifactsOf([...listed, artifact("evidence-area-0-3", { id: 5, expired: true })]),
		).toEqual({ problem: "evidence-area-0-3 has expired" });
	});

	it("names an expired or missing one", () => {
		expect(
			artifactsOf([artifact("evidence-area-0-1", { expired: true }), artifact("compliance")]),
		).toEqual({ problem: "evidence-area-0-1 has expired" });
		expect(artifactsOf([artifact("evidence-area-0-1")])).toEqual({
			problem: expect.stringMatching(/no compliance artifact/),
		});
		expect(artifactsOf([artifact("compliance")])).toEqual({
			problem: expect.stringMatching(/no evidence artifact/),
		});
	});
});

describe("the commit a run's reports name", () => {
	const report = (commit: string, runId = "1") => ({ identity: { commit, run: runId } });

	it("is the one commit the reports of that run name, files without an identity passed over", () => {
		expect(testedCommitOf([report("m1"), report("m1"), { attempted: {} }], "1")).toEqual({
			commit: "m1",
		});
	});

	it("is none where they name none, or more than one", () => {
		expect(testedCommitOf([], "1")).toEqual({ problem: "its reports name no commit tested" });
		expect(testedCommitOf([report("m1"), report("m2")], "1")).toEqual({
			problem: "its reports name more than one commit tested",
		});
	});

	it("is none where any report names another run, beside a full set of its own", () => {
		expect(testedCommitOf([report("m1"), report("m1", "2")], "1")).toEqual({
			problem: "a report of its names run 2, not this one",
		});
		expect(testedCommitOf([report("m1", "2")], "1")).toEqual({
			problem: "a report of its names run 2, not this one",
		});
	});
});

describe("whether the release may go on with a run's evidence", () => {
	const taken = {
		run: run({ id: 7 }),
		tested: { commit: head },
		jobs: { conformance: "success", "release-check": "success", compliance: "success" },
		recomputed: { releasable: true, told: "" },
		artifacts: [artifact("compliance")],
	};
	/** Examines each candidate by its id, from what the case lays out; a function, to throw. */
	const by =
		(found: Record<number, Examined | (() => never)>) =>
		(r: RunSeen): Examined => {
			const f = found[r.id];
			if (typeof f === "function") return f();
			if (!f) throw new Error(`run ${r.id} not laid out`);
			return f;
		};

	it("takes the newest run whose reports name the commit GitHub ran it on, its compliance passed", () => {
		expect(firstTaken(tag, [taken.run], by({ 7: taken }))).toEqual({ kind: "taken", ...taken });
	});

	it("refuses a run whose reports name another commit than the one GitHub ran it on", () => {
		const forged = { ...taken, run: run({ id: 8 }), tested: { commit: "f".repeat(40) } };
		expect(firstTaken(tag, [forged.run], by({ 8: forged }))).toEqual({
			kind: "stopped",
			problems: [expect.stringMatching(/its reports name f+ as tested, but GitHub ran it on h+/)],
		});
	});

	it("examines the candidates in turn, the newest first, and stops at the first that will do", () => {
		const examined: number[] = [];
		const older = run({ id: 3 });
		const result = firstTaken(tag, [taken.run, older], (r) => {
			examined.push(r.id);
			return by({
				7: taken,
				3: () => {
					throw new Error("unzip failed");
				},
			})(r);
		});
		expect(result.kind).toBe("taken");
		expect(examined).toEqual([7]);
	});

	it("tells a candidate that could not be examined, and goes on to the next", () => {
		const failing = run({ id: 9 });
		const throwing = () => {
			throw new Error("unzip failed");
		};
		expect(firstTaken(tag, [failing, taken.run], by({ 9: throwing, 7: taken })).kind).toBe("taken");
		expect(firstTaken(tag, [failing], by({ 9: throwing }))).toEqual({
			kind: "stopped",
			problems: [expect.stringMatching(/runs\/1: could not be examined \(unzip failed\)/)],
		});
	});

	it("takes a run only where the release's jobs passed, never one that skipped them", () => {
		const skipped = {
			...taken,
			run: run({ id: 11 }),
			jobs: { ...taken.jobs, "release-check": "skipped", conformance: "skipped" },
		};
		expect(firstTaken(tag, [skipped.run], by({ 11: skipped }))).toEqual({
			kind: "stopped",
			problems: [
				expect.stringMatching(
					/its conformance job ended skipped, its release-check job ended skipped: .*release branch's run/,
				),
			],
		});
		const unrun = { ...taken, run: run({ id: 12 }), jobs: { compliance: "success" } };
		expect(firstTaken(tag, [unrun.run], by({ 12: unrun })).kind).toBe("stopped");
	});

	it("takes a run only where its kept evidence, read again, still makes the release's compliance", () => {
		const thinned = {
			...taken,
			run: run({ id: 13 }),
			recomputed: { releasable: false, told: "runs that did not report: @mod/conformance-keys" },
		};
		expect(firstTaken(tag, [thinned.run], by({ 13: thinned }))).toEqual({
			kind: "stopped",
			problems: [
				expect.stringMatching(
					/the evidence it kept no longer makes the release's compliance \(runs that did not report: @mod\/conformance-keys\)/,
				),
			],
		});
	});

	it("stops, naming what is missing and what to do, where no run will do", () => {
		const none = firstTaken(tag, [], by({}));
		expect(none.kind === "stopped" && none.problems[0]).toMatch(
			/no successful CI run of a push of release\/1\.0\.1 at h+.*push that branch, or re-run its CI/,
		);
		const stopped = firstTaken(
			tag,
			[run({ id: 9 }), run({ id: 10 })],
			by({
				9: { ...taken, run: run({ id: 9 }), jobs: { ...taken.jobs, compliance: "failure" } },
				10: { run: run({ id: 10 }), problem: "evidence-area-0-1 has expired" },
			}),
		);
		expect(stopped).toEqual({
			kind: "stopped",
			problems: [
				expect.stringMatching(/its compliance job ended failure/),
				expect.stringMatching(/evidence-area-0-1 has expired/),
			],
		});
	});
});
