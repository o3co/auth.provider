import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { zipOf } from "./zip.ts";

const here = join(import.meta.dirname, "..");
const repository = "o3co/test";

/** A repository whose HEAD merges release/1.0.1 into main, as a release's tag commit does. */
function released(merge = true) {
	const dir = mkdtempSync(join(tmpdir(), "release-evidence-cli-"));
	const git = (...args: string[]) =>
		execFileSync(
			"git",
			["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...args],
			{
				cwd: dir,
				encoding: "utf8",
			},
		).trim();
	git("init", "-q", "-b", "main");
	mkdirSync(join(dir, ".github", "workflows"), { recursive: true });
	writeFileSync(join(dir, ".github", "workflows", "ci.yml"), "jobs: {}\n");
	git("add", ".");
	git("commit", "-q", "-m", "a");
	git("checkout", "-q", "-b", "release/1.0.1");
	writeFileSync(join(dir, "f.txt"), "h\n");
	git("add", ".");
	git("commit", "-q", "-m", "h");
	git("checkout", "-q", "main");
	if (merge) git("merge", "-q", "--no-ff", "release/1.0.1", "-m", "Merge release/1.0.1");
	git("update-ref", "refs/remotes/origin/main", merge ? "HEAD^1" : "HEAD");
	return { dir, head: merge ? git("rev-parse", "HEAD^2") : "" };
}

const node = (script: string, cwd: string, args: string[], env: Record<string, string>) =>
	spawnSync(process.execPath, [join(here, script), ...args], {
		cwd,
		encoding: "utf8",
		env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", ...env },
	});

describe("fetch", () => {
	/** A `gh` that answers nothing, or fails. */
	const gh = (fails: boolean) => {
		const bin = mkdtempSync(join(tmpdir(), "release-evidence-gh-"));
		writeFileSync(
			join(bin, "gh"),
			fails ? "#!/bin/sh\necho refused >&2\nexit 1\n" : "#!/bin/sh\nexit 0\n",
		);
		chmodSync(join(bin, "gh"), 0o755);
		return `${bin}:${process.env.PATH ?? ""}`;
	};

	it("stops where GitHub's answer cannot be had, writing nothing to be judged", () => {
		const { dir } = released();
		const out = join(dir, "..", `${Date.now()}-fetched`);
		const done = node("fetch.ts", dir, [out], { GITHUB_REPOSITORY: repository, PATH: gh(true) });
		expect(done.status).toBe(1);
		expect(done.stderr).toContain("GitHub could not be asked");
		expect(existsSync(join(out, "fetched.json"))).toBe(false);
	});

	it("writes no runs where GitHub answers none, and asks nothing of a tag that merged nothing", () => {
		const { dir } = released();
		const empty = node("fetch.ts", dir, [join(dir, "f1")], {
			GITHUB_REPOSITORY: repository,
			PATH: gh(false),
		});
		expect(empty.status).toBe(0);
		const lone = released(false);
		const none = node("fetch.ts", lone.dir, [join(lone.dir, "f2")], {
			GITHUB_REPOSITORY: repository,
			PATH: gh(true),
		});
		expect(none.status).toBe(0);
		expect(none.stdout).toContain("no second parent");
	});
});

describe("judge", () => {
	const ok = { conformance: "success", "release-check": "success", compliance: "success" };
	/** What fetch would have brought: one run of the release branch's head, its artifacts' archives laid out. */
	function brought(
		head: string,
		reports: readonly { name: string; data: string; mode?: number }[],
		over: { head?: string; repository?: string; examined?: boolean } = {},
	) {
		const fetched = mkdtempSync(join(tmpdir(), "release-evidence-fetched-"));
		mkdirSync(join(fetched, "zips"));
		writeFileSync(join(fetched, "zips", "1.zip"), zipOf([{ name: "compliance.json", data: "{}" }]));
		writeFileSync(join(fetched, "zips", "2.zip"), zipOf(reports));
		const run = {
			id: 7,
			attempt: 1,
			conclusion: "success",
			event: "push",
			path: ".github/workflows/ci.yml",
			headSha: head,
			headBranch: "release/1.0.1",
			repository,
			headRepository: repository,
			createdAt: "2026-10-27T00:00:00Z",
			url: "https://github.example/runs/7",
		};
		const artifacts = [
			{ id: 1, name: "compliance", expired: false, createdAt: run.createdAt },
			{ id: 2, name: "evidence-area-0-1", expired: false, createdAt: run.createdAt },
		];
		const jobs = Object.entries(ok).map(([name, conclusion]) => ({ name, conclusion }));
		writeFileSync(
			join(fetched, "fetched.json"),
			JSON.stringify({
				repository: over.repository ?? repository,
				head: over.head ?? head,
				runs: [run],
				examined: over.examined === false ? {} : { "7": { jobs, artifacts } },
			}),
		);
		return fetched;
	}
	const judged = (dir: string, fetched: string, more: Record<string, string> = {}) =>
		node("judge.ts", dir, [fetched, join(fetched, "out")], {
			GITHUB_REPOSITORY: repository,
			GITHUB_REF_NAME: "v1.0.1",
			...more,
		});
	const report = (commit: string, run = "7") => JSON.stringify({ identity: { commit, run } });

	it("refuses to judge holding a credential", () => {
		const { dir, head } = released();
		for (const name of ["GH_TOKEN", "GITHUB_TOKEN"]) {
			const done = judged(dir, brought(head, []), { [name]: "x" });
			expect([done.status, done.stderr]).toEqual([
				1,
				expect.stringContaining("holding no credential"),
			]);
		}
	});

	it("refuses what fetch brought of another head or another repository", () => {
		const { dir, head } = released();
		for (const over of [{ head: "0".repeat(40) }, { repository: "someone/else" }]) {
			const done = judged(dir, brought(head, [], over));
			expect([done.status, done.stderr]).toEqual([1, expect.stringContaining("fetch asked after")]);
		}
	});

	it("refuses a run fetch brought nothing of", () => {
		const { dir, head } = released();
		const done = judged(dir, brought(head, [], { examined: false }));
		expect(done.stderr).toContain("fetch brought nothing of it");
	});

	it("refuses an archive holding a link or a name that lands outside, before unpacking it", () => {
		const { dir, head } = released();
		for (const [entry, told] of [
			[{ name: "r.json", data: "/etc/passwd", mode: 0o120777 }, "r.json is a link"],
			[{ name: "../escape.json", data: report(head) }, '"../escape.json" would land outside'],
			[{ name: "/abs.json", data: report(head) }, '"/abs.json" would land outside'],
		] as const) {
			const fetched = brought(head, [{ name: "ok.json", data: report(head) }, entry]);
			const done = judged(dir, fetched);
			expect([done.status, done.stderr]).toEqual([1, expect.stringContaining(told)]);
			expect(existsSync(join(fetched, "..", "escape.json"))).toBe(false);
		}
	});

	it("refuses reports beside which one names another run", () => {
		const { dir, head } = released();
		const done = judged(
			dir,
			brought(head, [
				{ name: "a.json", data: report(head) },
				{ name: "b.json", data: report(head, "8") },
			]),
		);
		expect(done.stderr).toContain("a report of its names run 8, not this one");
	});

	it("refuses reports naming another commit than the one GitHub ran the run on", () => {
		const { dir, head } = released();
		const done = judged(dir, brought(head, [{ name: "a.json", data: report("f".repeat(40)) }]));
		expect(done.stderr).toMatch(/its reports name f+ as tested, but GitHub ran it on/);
	});
});
