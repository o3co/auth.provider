#!/usr/bin/env node
/**
 * Before anything is published: finds the CI run that tested the tag's tree and keeps its evidence in
 * the directory named, with a manifest of what it is; where no run will do, stops the release, naming
 * why and what to do. Run in the tag's checkout, `gh` authenticated to read the repository's runs.
 */
import { spawnSync } from "node:child_process";
import {
	closeSync,
	cpSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	type ArtifactSeen,
	artifactsOf,
	candidatesOf,
	type Examined,
	firstTaken,
	type RunSeen,
	releasePullOf,
	testedCommitOf,
} from "./evidence.ts";

const directory = process.argv[2];
const repository = process.env.GITHUB_REPOSITORY;
if (!directory || !repository) {
	console.error(
		"release-evidence: name the directory to keep the evidence in, with GITHUB_REPOSITORY set",
	);
	process.exit(2);
}
const ran = (command: string, args: readonly string[]) => {
	const answer = spawnSync(command, args, { encoding: "utf8", maxBuffer: 1 << 28 });
	if (answer.status !== 0) throw new Error(`${command} ${args.join(" ")}: ${answer.stderr.trim()}`);
	return answer.stdout.trim();
};
const git = (...args: string[]) => ran("git", args);
/** Each JSON value a paginated API answer's jq filter writes, one a line. */
const listed = <T>(path: string, filter: string): T[] =>
	// `tojson`, as jq writes a string raw.
	ran("gh", ["api", "--paginate", path, "--jq", `${filter} | tojson`])
		.split("\n")
		.filter((line) => line !== "")
		.map((line) => JSON.parse(line) as T);
const stop = (problems: readonly string[]): never => {
	for (const problem of problems) console.error(`release-evidence: ${problem}`);
	console.error("release-evidence: nothing may be published");
	process.exit(1);
};

const repo = `repos/${repository}`;
const commit = git("rev-parse", "HEAD");
const pull = releasePullOf(
	listed<Parameters<typeof releasePullOf>[0][number]>(
		`${repo}/commits/${commit}/pulls`,
		".[] | {number, mergeCommit: .merge_commit_sha, base: .base.ref, head: .head.sha, branch: .head.ref}",
	),
	commit,
);
if (pull === undefined) {
	stop([
		`the tag's commit ${commit} merged no pull request to main: tag the merge commit of the release pull request on main`,
	]);
}
const release = pull as NonNullable<typeof pull>;
const tag = { commit, tree: git("rev-parse", "HEAD^{tree}"), head: release.head };
// Once a pull request is merged, its runs may list no pull request; their head and branch name it then.
const runs = listed<RunSeen>(
	`${repo}/actions/workflows/ci.yml/runs?event=pull_request&head_sha=${release.head}&per_page=100`,
	".workflow_runs[] | {id, attempt: .run_attempt, conclusion, event, headSha: .head_sha, headBranch: .head_branch, baseRefs: [.pull_requests[].base.ref], createdAt: .created_at, url: .html_url}",
);

const work = mkdtempSync(join(tmpdir(), "release-evidence-"));
const walk = (dir: string): string[] =>
	readdirSync(dir).flatMap((entry) => {
		const path = join(dir, entry);
		return statSync(path).isDirectory() ? walk(path) : [path];
	});

/** A candidate's artifacts downloaded and unpacked, the commit its reports tested with that commit's tree, and how its jobs ended. */
function examined(run: RunSeen): Examined {
	const chosen = artifactsOf(
		listed<ArtifactSeen>(
			`${repo}/actions/runs/${run.id}/artifacts?per_page=100`,
			".artifacts[] | {id, name, expired, createdAt: .created_at}",
		),
	);
	if ("problem" in chosen) return { run, problem: chosen.problem };
	const dir = join(work, String(run.id));
	for (const a of chosen.take) {
		const zip = join(work, `${a.id}.zip`);
		// Written to the file as it comes, so the archive's bytes are never read as text.
		const out = openSync(zip, "w");
		const got = spawnSync("gh", ["api", `${repo}/actions/artifacts/${a.id}/zip`], {
			stdio: ["ignore", out, "pipe"],
		});
		closeSync(out);
		if (got.status !== 0) return { run, problem: `${a.name} could not be downloaded` };
		ran("unzip", ["-q", "-o", zip, "-d", join(dir, a.name)]);
	}
	const reports = walk(dir)
		.filter((f) => f.endsWith(".json"))
		.flatMap((f) => {
			try {
				return [JSON.parse(readFileSync(f, "utf8")) as unknown];
			} catch {
				return [];
			}
		});
	const commit = testedCommitOf(reports, String(run.id));
	if (commit === undefined) return { run, problem: "its reports name no one commit tested" };
	const tree = ran("gh", ["api", `${repo}/git/commits/${commit}`, "--jq", ".tree.sha"]);
	const jobs = Object.fromEntries(
		listed<{ name: string; conclusion: string | null }>(
			`${repo}/actions/runs/${run.id}/jobs?per_page=100`,
			".jobs[] | {name, conclusion}",
		).map((j) => [j.name, j.conclusion]),
	);
	return { run, tested: { commit, tree }, jobs, artifacts: chosen.take };
}

try {
	const verdict = firstTaken(tag, candidatesOf(runs, release), examined);
	if (verdict.kind === "stopped") stop(verdict.problems);
	else {
		const at = resolve(directory);
		mkdirSync(at, { recursive: true });
		cpSync(join(work, String(verdict.run.id)), join(at, "ci"), { recursive: true });
		const manifest = {
			tag: { commit: tag.commit, tree: tag.tree },
			run: {
				id: verdict.run.id,
				attempt: verdict.run.attempt,
				url: verdict.run.url,
				tested: verdict.tested,
			},
			artifacts: verdict.artifacts.map((a) => a.name),
		};
		writeFileSync(join(at, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
		console.log(
			`release-evidence: ${verdict.artifacts.length} artifacts of ${verdict.run.url}, which tested the tag's tree ${tag.tree}`,
		);
	}
} finally {
	rmSync(work, { recursive: true, force: true });
}
