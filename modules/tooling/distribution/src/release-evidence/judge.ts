#!/usr/bin/env node
/**
 * Judges, holding no credential, what `fetch` brought: whether the tag is a release's, which CI run
 * tested its tree, and whether that run's evidence still makes the release's compliance. Keeps the
 * run's evidence in the directory named, with a manifest of what it is; where no run will do, stops
 * the release, naming why and what to do. Run in the tag's checkout, with main's history fetched.
 */
import { spawnSync } from "node:child_process";
import {
	cpSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { cacheProblems } from "../workflow-caches/caches.ts";
import {
	type ArtifactSeen,
	artifactsOf,
	candidatesOf,
	type Examined,
	firstTaken,
	type RunSeen,
	tagOf,
	testedCommitOf,
} from "./evidence.ts";

const [fetched, directory] = process.argv.slice(2);
const repository = process.env.GITHUB_REPOSITORY;
const tagName = process.env.GITHUB_REF_NAME;
const stop = (problems: readonly string[]): never => {
	for (const problem of problems) console.error(`release-evidence: ${problem}`);
	console.error("release-evidence: nothing may be published");
	process.exit(1);
};
if (!fetched || !directory || !repository || !tagName) {
	console.error(
		"release-evidence judge: name what fetch wrote and the directory to keep the evidence in, with GITHUB_REPOSITORY and GITHUB_REF_NAME set",
	);
	process.exit(2);
}
if (process.env.GH_TOKEN || process.env.GITHUB_TOKEN) {
	stop(["the judge runs holding no credential, and this step holds one"]);
}

const git = (...args: string[]) => {
	const answer = spawnSync("git", args, { encoding: "utf8" });
	return { ok: answer.status === 0, out: answer.stdout.trim() };
};
const ran = (command: string, args: readonly string[]) => {
	const answer = spawnSync(command, args, { encoding: "utf8", maxBuffer: 1 << 28 });
	if (answer.status !== 0) throw new Error(`${command} ${args.join(" ")}: ${answer.stderr.trim()}`);
	return answer.stdout.trim();
};

const brought = JSON.parse(readFileSync(join(fetched, "fetched.json"), "utf8")) as {
	repository: string;
	head: string | null;
	runs: RunSeen[];
	examined: Record<
		string,
		{ jobs: { name: string; conclusion: string | null }[]; artifacts: ArtifactSeen[] }
	>;
};

// The tag, from the checkout alone.
const commit = git("rev-parse", "HEAD").out;
const parents = git("rev-list", "--parents", "-n", "1", "HEAD").out.split(" ").slice(1);
const second = parents[1];
// The tag's tree, wherever the judge is run from.
const root = git("rev-parse", "--show-toplevel").out;
const seen = {
	name: tagName,
	commit,
	tree: git("rev-parse", "HEAD^{tree}").out,
	parents,
	headTree: second === undefined ? undefined : git("rev-parse", `${second}^{tree}`).out,
	firstParentOnMain:
		parents[0] !== undefined &&
		git("merge-base", "--is-ancestor", parents[0], "refs/remotes/origin/main").ok,
	cacheProblems: cacheProblems(
		".github/workflows/ci.yml",
		(p) => readFileSync(join(root, p), "utf8"),
		"ci",
	),
};
const found = tagOf(seen);
if ("problems" in found) stop(found.problems);
const tag = (found as Extract<typeof found, { tag: unknown }>).tag;
if (brought.repository !== repository || brought.head !== tag.head) {
	stop([
		`fetch asked after ${brought.head} in ${brought.repository}, not ${tag.head} in ${repository}`,
	]);
}

const work = mkdtempSync(join(tmpdir(), "release-evidence-"));
const walk = (dir: string): string[] =>
	readdirSync(dir).flatMap((entry) => {
		const path = join(dir, entry);
		return statSync(path).isDirectory() ? walk(path) : [path];
	});

/**
 * The release's compliance (spec-checklist's, with `--release`) read again over the evidence kept,
 * as the run it is from and the commit it tested: an artifact gone since CI passed leaves an expected
 * run unreported. The tag's tree is the tested commit's, so its checklist and tests are the ones read.
 */
function recomputed(run: RunSeen, tested: string, dir: string) {
	const read = spawnSync(
		"pnpm",
		["--silent", "--filter", "@mod/spec-checklist", "run", "compliance", dir, "--release"],
		{
			encoding: "utf8",
			maxBuffer: 1 << 28,
			env: { ...process.env, SPEC_EVIDENCE_COMMIT: tested, GITHUB_RUN_ID: String(run.id) },
		},
	);
	// What it tells, from the table it wrote beside the reports: the runs that did not report, the items that block.
	let told = `${read.stderr ?? ""}`.trim().split("\n").slice(-3).join(" ");
	try {
		const table = JSON.parse(readFileSync(join(dir, "compliance.json"), "utf8")) as {
			missingRuns?: string[];
			items?: { status?: string }[];
		};
		const blocking = (table.items ?? []).filter((i) =>
			["failed", "incomplete", "unverified"].includes(i.status ?? ""),
		).length;
		told =
			[
				table.missingRuns?.length
					? `runs that did not report: ${table.missingRuns.join(", ")}`
					: "",
				blocking > 0 ? `${blocking} items failed, incomplete or unverified` : "",
			]
				.filter((t) => t !== "")
				.join("; ") || told;
	} catch {
		// No table written: what it printed on standard error is told instead.
	}
	return { releasable: read.status === 0, told };
}

/** A candidate's artifacts, as fetch brought them, unpacked; the commit its reports name; how its jobs ended. */
function examined(run: RunSeen): Examined {
	const of = brought.examined[String(run.id)];
	if (of === undefined) return { run, problem: "fetch brought nothing of it" };
	const chosen = artifactsOf(of.artifacts);
	if ("problem" in chosen) return { run, problem: chosen.problem };
	const dir = join(work, String(run.id));
	for (const a of chosen.take) {
		ran("unzip", [
			"-q",
			"-o",
			join(fetched as string, "zips", `${a.id}.zip`),
			"-d",
			join(dir, a.name),
		]);
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
	const tested = testedCommitOf(reports, String(run.id));
	if (tested === undefined) return { run, problem: "its reports name no one commit tested" };
	return {
		run,
		tested: { commit: tested },
		jobs: Object.fromEntries(of.jobs.map((j) => [j.name, j.conclusion])),
		recomputed: recomputed(run, tested, dir),
		artifacts: chosen.take,
	};
}

try {
	const verdict = firstTaken(tag, candidatesOf(brought.runs, tag, repository), examined);
	if (verdict.kind === "stopped") stop(verdict.problems);
	else {
		const at = resolve(directory);
		mkdirSync(at, { recursive: true });
		cpSync(join(work, String(verdict.run.id)), join(at, "ci"), { recursive: true });
		const manifest = {
			tag: { name: tagName, commit: tag.commit, tree: tag.tree },
			run: {
				repository,
				id: verdict.run.id,
				attempt: verdict.run.attempt,
				url: verdict.run.url,
				branch: tag.branch,
				tested: { commit: tag.head, tree: tag.tree },
			},
			artifacts: verdict.artifacts.map((a) => a.name),
		};
		writeFileSync(join(at, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
		console.log(
			`release-evidence: ${verdict.artifacts.length} artifacts of ${verdict.run.url}, which tested ${tag.head} on ${tag.branch}, of the tag's tree ${tag.tree}`,
		);
	}
} finally {
	rmSync(work, { recursive: true, force: true });
}
