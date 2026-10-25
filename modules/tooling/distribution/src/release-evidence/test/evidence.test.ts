import { describe, expect, it } from "vitest";
import {
	type ArtifactSeen,
	artifactsOf,
	candidatesOf,
	type RunSeen,
	releasePullOf,
	testedCommitOf,
	verdictOf,
} from "../evidence.ts";

const head = "h".repeat(40);
const run = (over: Partial<RunSeen>): RunSeen => ({
	id: 1,
	attempt: 1,
	conclusion: "success",
	event: "pull_request",
	headSha: head,
	headBranch: "release/1.0",
	baseRefs: ["main"],
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
const tag = { commit: "c".repeat(40), tree: "t".repeat(40), head };
const pull = { number: 5, head, branch: "release/1.0" };

describe("the runs that may hold a release's evidence", () => {
	it("is the pull request to main the tag's merge commit merged", () => {
		const seen = (number: number, mergeCommit: string, base: string) => ({
			number,
			mergeCommit,
			base,
			head,
			branch: "release/1.0",
		});
		expect(
			releasePullOf(
				[seen(4, "other", "main"), seen(5, tag.commit, "main"), seen(6, tag.commit, "develop")],
				tag.commit,
			),
		).toEqual(pull);
		expect(releasePullOf([seen(4, "other", "main")], tag.commit)).toBeUndefined();
	});

	it("takes CI's successful runs of that pull request, its head and branch, the newest first", () => {
		const older = run({ id: 1, createdAt: "2026-10-25T01:00:00Z" });
		const newer = run({ id: 2, attempt: 2, createdAt: "2026-10-26T01:00:00Z" });
		const found = candidatesOf(
			[
				older,
				newer,
				run({ id: 3, conclusion: "failure" }),
				run({ id: 4, baseRefs: ["develop"] }),
				run({ id: 5, event: "push" }),
				run({ id: 6, headSha: "x".repeat(40) }),
				run({ id: 7, headBranch: "develop" }),
				// Once the pull request is merged, its runs may list none.
				run({ id: 8, baseRefs: [], createdAt: "2026-10-24T01:00:00Z" }),
			],
			pull,
		);
		expect(found.map((r) => r.id)).toEqual([2, 1, 8]);
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
		).toEqual({
			problem: "evidence-area-0-3 has expired",
		});
	});

	it("names an expired or missing one, and what to run again", () => {
		const expired = artifactsOf([
			artifact("evidence-area-0-1", { expired: true }),
			artifact("compliance"),
		]);
		expect(expired).toEqual({
			problem: "evidence-area-0-1 has expired",
		});
		expect(artifactsOf([artifact("evidence-area-0-1")])).toEqual({
			problem: expect.stringMatching(/no compliance artifact/),
		});
		expect(artifactsOf([artifact("compliance")])).toEqual({
			problem: expect.stringMatching(/no evidence artifact/),
		});
	});
});

describe("the commit a run tested", () => {
	const report = (commit: string, runId = "1") => ({ identity: { commit, run: runId } });

	it("is the one commit the run's reports name", () => {
		expect(
			testedCommitOf([report("m1"), report("m1"), report("x", "2"), { attempted: {} }], "1"),
		).toBe("m1");
	});

	it("is none where the reports name no commit, or more than one", () => {
		expect(testedCommitOf([], "1")).toBeUndefined();
		expect(testedCommitOf([report("m1"), report("m2")], "1")).toBeUndefined();
	});
});

describe("whether the release may go on with a run's evidence", () => {
	const taken = {
		run: run({ id: 7 }),
		tested: { commit: "m", tree: tag.tree },
		compliance: "success",
		artifacts: [artifact("compliance")],
	};

	it("takes the newest run that tested the tag's tree with its compliance passed", () => {
		const moved = { ...taken, run: run({ id: 8 }), tested: { commit: "n", tree: "other" } };
		expect(verdictOf(tag, [moved, taken])).toEqual({ kind: "taken", ...taken });
	});

	it("stops, naming what is missing and what to do, where no run will do", () => {
		const none = verdictOf(tag, []);
		expect(none.kind).toBe("stopped");
		expect(none.kind === "stopped" && none.problems[0]).toMatch(
			/no successful CI run of a pull request to main tested .*re-run/,
		);
		const stopped = verdictOf(tag, [
			{ ...taken, tested: { commit: "n", tree: "other" } },
			{ ...taken, run: run({ id: 9 }), compliance: "failure" },
			{ run: run({ id: 10 }), problem: "evidence-area-0-1 has expired" },
		]);
		expect(stopped).toEqual({
			kind: "stopped",
			problems: [
				expect.stringMatching(/tested tree other, but the tag's tree is t+: main moved/),
				expect.stringMatching(/its compliance job ended failure/),
				expect.stringMatching(/evidence-area-0-1 has expired/),
			],
		});
	});
});
