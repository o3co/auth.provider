#!/usr/bin/env node
/**
 * Fetches, with the token it is given and nothing else, what the release's evidence is judged from:
 * CI's runs of a push of the tag's merged release branch head, and for each that succeeded, its jobs,
 * its artifacts' list and its evidence artifacts. It judges nothing, and imports node's own modules
 * alone, so it runs before anything is installed. Where GitHub's answer cannot be had, it stops: no
 * answer is ever taken for an answer of no runs.
 */
import { spawnSync } from "node:child_process";
import { closeSync, mkdirSync, openSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { succeeded } from "./spawned.ts";

const directory = process.argv[2];
// The repository whose CI tested the release: this one, or the one a security release was tested in.
const repository = process.env.EVIDENCE_REPOSITORY || process.env.GITHUB_REPOSITORY;
if (!directory || !repository) {
	console.error(
		"release-evidence fetch: name the directory to fetch into, with GITHUB_REPOSITORY set",
	);
	process.exit(2);
}
const stop = (problem: string): never => {
	console.error(`release-evidence fetch: ${problem}`);
	console.error("release-evidence fetch: GitHub could not be asked; nothing may be published");
	process.exit(1);
};
const ran = (command: string, args: readonly string[]) => {
	const answer = spawnSync(command, args, { encoding: "utf8", maxBuffer: 1 << 28 });
	return { ok: succeeded(answer), out: answer.stdout.trim(), err: answer.stderr.trim() };
};
/** Each JSON value a paginated API answer's jq filter writes, one a line; the answer failing stops. */
const listed = <T>(path: string, filter: string): T[] => {
	const answer = ran("gh", ["api", "--paginate", path, "--jq", `${filter} | tojson`]);
	if (!answer.ok) stop(`${path}: ${answer.err}`);
	return answer.out
		.split("\n")
		.filter((line) => line !== "")
		.map((line) => JSON.parse(line) as T);
};

const repo = `repos/${repository}`;
const at = resolve(directory);
mkdirSync(join(at, "zips"), { recursive: true });

// The release branch's head the tag's commit merged; a commit with no second parent has none to ask after.
const second = ran("git", ["rev-parse", "--verify", "--quiet", "HEAD^2"]);
const head = second.ok ? second.out : null;
const runs =
	head === null
		? []
		: listed<Record<string, unknown>>(
				`${repo}/actions/workflows/ci.yml/runs?event=push&head_sha=${head}&per_page=100`,
				".workflow_runs[] | {id, attempt: .run_attempt, conclusion, event, path, headSha: .head_sha, headBranch: .head_branch, repository: .repository.full_name, headRepository: .head_repository.full_name, createdAt: .created_at, url: .html_url}",
			);

const examined: Record<string, { jobs: unknown[]; artifacts: unknown[] }> = {};
for (const run of runs.filter((r) => r.conclusion === "success" && r.headSha === head)) {
	const id = String(run.id);
	const jobs = listed(
		`${repo}/actions/runs/${id}/jobs?filter=latest&per_page=100`,
		".jobs[] | {name, conclusion}",
	);
	const artifacts = listed<{ id: number; name: string; expired: boolean }>(
		`${repo}/actions/runs/${id}/artifacts?per_page=100`,
		".artifacts[] | {id, name, expired, createdAt: .created_at}",
	);
	for (const a of artifacts) {
		if (a.expired || !(a.name.startsWith("evidence-") || a.name === "compliance")) continue;
		// Written to the file as it comes, so the archive's bytes are never read as text.
		const out = openSync(join(at, "zips", `${a.id}.zip`), "w");
		const got = spawnSync("gh", ["api", `${repo}/actions/artifacts/${a.id}/zip`], {
			stdio: ["ignore", out, "pipe"],
		});
		closeSync(out);
		if (!succeeded(got)) stop(`artifact ${a.name} of run ${id} could not be downloaded`);
	}
	examined[id] = { jobs, artifacts };
}

writeFileSync(
	join(at, "fetched.json"),
	`${JSON.stringify({ repository, head, runs, examined }, null, 2)}\n`,
);
console.log(
	`release-evidence fetch: ${runs.length} runs of ${head ?? "no second parent"}, ${Object.keys(examined).length} examined`,
);
