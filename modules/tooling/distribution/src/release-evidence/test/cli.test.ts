import { execFileSync, spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { unicodePath, type ZipFile, zipOf } from "./zip.ts";

// Each test runs git and node a few times over, slow on a loaded machine.
vi.setConfig({ testTimeout: 60_000 });

const here = join(import.meta.dirname, "..");
const repository = "o3co/test";

/** A repository whose HEAD merges release/1.0.1 into main, as a release's tag commit does. */
/** How the release's tag is written: annotated with the lines given, lightweight, on another commit, or not at all. */
type Tagged = {
	readonly lines?: readonly string[];
	readonly lightweight?: boolean;
	readonly on?: string;
	readonly none?: boolean;
	/** A message of this many bytes, past what a process's output is read to. */
	readonly long?: number;
};

function released(merge = true, declared = false, tagged: Tagged = {}) {
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
	const lines = tagged.lines ?? (declared ? ["Release-Evidence: security"] : []);
	const on = tagged.on ?? "HEAD";
	if (tagged.lightweight) git("tag", "v1.0.1", on);
	else if (tagged.long) {
		const message = join(dir, "..", `${dir.split("/").pop()}-message`);
		writeFileSync(message, `v1.0.1\n\n${"x".repeat(tagged.long)}\nRelease-Evidence: security\n`);
		git("tag", "-a", "v1.0.1", "-F", message, on);
	} else if (!tagged.none)
		git("tag", "-a", "v1.0.1", "-m", "v1.0.1", ...lines.flatMap((l) => ["-m", l]), on);
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

	it("asks after the repository it is given to read, the security repository's included", () => {
		const { dir } = released();
		const bin = mkdtempSync(join(tmpdir(), "release-evidence-gh-"));
		const asked = join(bin, "asked");
		writeFileSync(join(bin, "gh"), `#!/bin/sh\necho "$@" >> ${asked}\nexit 0\n`);
		chmodSync(join(bin, "gh"), 0o755);
		const done = node("fetch.ts", dir, [join(dir, "f3")], {
			GITHUB_REPOSITORY: repository,
			EVIDENCE_REPOSITORY: "o3co/secure",
			PATH: `${bin}:${process.env.PATH ?? ""}`,
		});
		expect(done.status).toBe(0);
		expect(readFileSync(asked, "utf8")).toContain(
			"repos/o3co/secure/actions/workflows/ci.yml/runs",
		);
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
		reports: readonly ZipFile[],
		over: { head?: string; repository?: string; examined?: boolean; runs?: "none" | "failed" } = {},
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
			repository: over.repository ?? repository,
			headRepository: over.repository ?? repository,
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
				runs:
					over.runs === "none"
						? []
						: over.runs === "failed"
							? [{ ...run, conclusion: "failure" }]
							: [run],
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

	/** A stand-in for the release's compliance, letting the release go on. */
	const passing = () => {
		const bin = mkdtempSync(join(tmpdir(), "release-evidence-compliance-"));
		writeFileSync(join(bin, "compliance"), "#!/bin/sh\necho '{}' > \"$1/compliance.json\"\n");
		chmodSync(join(bin, "compliance"), 0o755);
		return join(bin, "compliance");
	};
	const routeOf = (output: string) => readFileSync(output, "utf8");

	it("hands the release to the security repository where its tag declares one, whatever ran here, and never else", () => {
		const declared = released(true, true);
		for (const [n, over] of [{ runs: "none" }, {}, { runs: "failed" }].entries()) {
			const output = join(declared.dir, "..", `${Date.now()}-${n}-output`);
			const done = judged(
				declared.dir,
				brought(declared.head, [], over as { runs?: "none" | "failed" }),
				{
					GITHUB_OUTPUT: output,
				},
			);
			expect([done.status, routeOf(output)]).toEqual([0, "route=security\n"]);
		}
		const plain = released();
		for (const runs of ["none", "failed"] as const) {
			const done = judged(plain.dir, brought(plain.head, [], { runs }));
			expect([done.status, done.stderr]).toEqual([
				1,
				expect.stringContaining("no successful CI run"),
			]);
		}
	});

	it("reads the tag as pushed, refusing one it cannot read, of another commit, or declaring another value", () => {
		for (const [tagged, told, more] of [
			[{ none: true }, "cannot be read in this checkout", {}],
			[{ long: 2 << 20 }, "message of the tag v1.0.1 cannot be read", {}],
			// Just past the default buffer: git may exit 0 with its output cut short, its last line lost.
			[{ long: (1 << 20) + 64 }, "message of the tag v1.0.1 cannot be read", {}],
			[{ on: "HEAD^1" }, "are not one commit", {}],
			[{}, "are not one commit", { GITHUB_SHA: "0".repeat(40) }],
			[
				{ lines: ["Release-Evidence: public"] },
				"declares Release-Evidence otherwise than security",
				{},
			],
			[
				{ lines: ["Release-Evidence: security", "release-evidence: SECURITY"] },
				"declares Release-Evidence otherwise than security",
				{},
			],
		] as const) {
			const { dir, head } = released(true, false, tagged);
			const done = judged(dir, brought(head, [], { runs: "none" }), more);
			expect([done.status, done.stderr], told).toEqual([1, expect.stringContaining(told)]);
		}
	});

	it("reads a lightweight tag as declaring nothing", () => {
		const { dir, head } = released(true, false, { lightweight: true });
		const done = judged(dir, brought(head, [], { runs: "none" }));
		expect([done.status, done.stderr]).toEqual([
			1,
			expect.stringContaining("no successful CI run"),
		]);
	});

	it("takes no run of the security repository for a tag that declares no security release", () => {
		const { dir, head } = released();
		const done = judged(dir, brought(head, [], { repository: "o3co/secure" }), {
			EVIDENCE_REPOSITORY: "o3co/secure",
		});
		expect([done.status, done.stderr]).toEqual([
			1,
			expect.stringContaining("declares no security release"),
		]);
	});

	it("takes a run whose evidence makes the release's compliance, telling the route it came by", () => {
		const reports = (head: string) => [{ name: "a.json", data: report(head) }];
		const plain = released();
		const output = join(plain.dir, "..", `${Date.now()}-public`);
		const fetched = brought(plain.head, reports(plain.head));
		const taken = judged(plain.dir, fetched, {
			GITHUB_OUTPUT: output,
			RELEASE_EVIDENCE_COMPLIANCE: passing(),
		});
		expect([taken.status, routeOf(output)]).toEqual([0, "route=public\n"]);
		const manifest = JSON.parse(readFileSync(join(fetched, "out", "manifest.json"), "utf8"));
		expect(manifest.run).toMatchObject({ repository, id: 7, branch: "release/1.0.1" });

		const declared = released(true, true);
		const secure = join(declared.dir, "..", `${Date.now()}-security`);
		const fromSecurity = judged(
			declared.dir,
			brought(declared.head, reports(declared.head), { repository: "o3co/secure" }),
			{
				EVIDENCE_REPOSITORY: "o3co/secure",
				GITHUB_OUTPUT: secure,
				RELEASE_EVIDENCE_COMPLIANCE: passing(),
			},
		);
		expect([fromSecurity.status, routeOf(secure)]).toEqual([0, "route=security\n"]);
	});

	it("judges the repository it is given, refusing what fetch brought of another", () => {
		const { dir, head } = released();
		const done = judged(dir, brought(head, []), { EVIDENCE_REPOSITORY: "o3co/secure" });
		expect([done.status, done.stderr]).toEqual([1, expect.stringContaining("in o3co/test, not")]);
	});

	it("refuses a run fetch brought nothing of", () => {
		const { dir, head } = released();
		const done = judged(dir, brought(head, [], { examined: false }));
		expect(done.stderr).toContain("fetch brought nothing of it");
	});

	it("refuses an archive holding a link or a name that lands outside, before unpacking it", () => {
		const { dir, head } = released();
		for (const [entry, told] of [
			[
				{ name: "r.json", data: "/etc/passwd", mode: 0o120777 },
				"r.json is neither a file nor a directory",
			],
			[
				{ name: "b.json", data: "/etc", mode: 0o120777, host: 16 },
				"b.json is neither a file nor a directory",
			],
			[{ name: "../escape.json", data: report(head) }, '"../escape.json" would land outside'],
			[{ name: "/abs.json", data: report(head) }, '"/abs.json" would land outside'],
			[
				{
					name: "report.json",
					data: report(head),
					centralExtra: unicodePath("report.json", "../escape.json"),
				},
				"report.json is named otherwise",
			],
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

	it("never takes the compliance stand-in in a GitHub Actions run, nor a compliance that wrote no table", () => {
		const { dir, head } = released();
		const bin = mkdtempSync(join(tmpdir(), "release-evidence-compliance-"));
		writeFileSync(join(bin, "c"), "#!/bin/sh\necho '{}' > \"$1/compliance.json\"\n");
		chmodSync(join(bin, "c"), 0o755);
		const done = judged(dir, brought(head, [{ name: "a.json", data: report(head) }]), {
			RELEASE_EVIDENCE_COMPLIANCE: join(bin, "c"),
			GITHUB_ACTIONS: "true",
		});
		expect([done.status, done.stderr]).toEqual([
			1,
			expect.stringContaining("no longer makes the release's compliance"),
		]);
	});

	it("takes a release branch's run from GitHub's answers to its evidence kept, as the release runs fetch and judge", () => {
		const { dir, head } = released();
		const served = mkdtempSync(join(tmpdir(), "release-evidence-served-"));
		writeFileSync(join(served, "1.zip"), zipOf([{ name: "compliance.json", data: "{}" }]));
		writeFileSync(join(served, "2.zip"), zipOf([{ name: "a.json", data: report(head) }]));
		const at = "2026-10-27T00:00:00Z";
		const answers = {
			runs: [
				{
					id: 7,
					attempt: 1,
					conclusion: "success",
					event: "push",
					path: ".github/workflows/ci.yml",
					headSha: head,
					headBranch: "release/1.0.1",
					repository,
					headRepository: repository,
					createdAt: at,
					url: "https://github.example/runs/7",
				},
			],
			jobs: ["conformance", "release-check", "compliance"].map((name) => ({
				name,
				conclusion: "success",
			})),
			artifacts: [
				{ id: 1, name: "compliance", expired: false, createdAt: at },
				{ id: 2, name: "evidence-area-0-1", expired: false, createdAt: at },
			],
		};
		const bin = mkdtempSync(join(tmpdir(), "release-evidence-gh-"));
		writeFileSync(
			join(bin, "gh"),
			`#!${process.execPath}
const fs = require("node:fs");
const answers = ${JSON.stringify(answers)};
const path = process.argv.find((a) => a.startsWith("repos/"));
const zip = /artifacts\\/(\\d+)\\/zip$/.exec(path);
if (zip) process.stdout.write(fs.readFileSync(${JSON.stringify(served)} + "/" + zip[1] + ".zip"));
else for (const line of path.includes("/workflows/") ? answers.runs : path.includes("/jobs") ? answers.jobs : answers.artifacts) console.log(JSON.stringify(line));
`,
		);
		chmodSync(join(bin, "gh"), 0o755);
		const fetched = join(served, "fetched");
		const fetching = node("fetch.ts", dir, [fetched], {
			GITHUB_REPOSITORY: repository,
			PATH: `${bin}:${process.env.PATH ?? ""}`,
		});
		expect([fetching.status, fetching.stderr]).toEqual([0, ""]);

		const compliance = (status: number) => {
			const stand = join(mkdtempSync(join(tmpdir(), "release-evidence-compliance-")), "c");
			writeFileSync(stand, `#!/bin/sh\necho '{}' > "$1/compliance.json"\nexit ${status}\n`);
			chmodSync(stand, 0o755);
			return stand;
		};
		const refused = node("judge.ts", dir, [fetched, join(served, "refused")], {
			GITHUB_REPOSITORY: repository,
			GITHUB_REF_NAME: "v1.0.1",
			RELEASE_EVIDENCE_COMPLIANCE: compliance(1),
		});
		expect([refused.status, existsSync(join(served, "refused", "manifest.json"))]).toEqual([
			1,
			false,
		]);

		const kept = join(served, "kept");
		const taken = node("judge.ts", dir, [fetched, kept], {
			GITHUB_REPOSITORY: repository,
			GITHUB_REF_NAME: "v1.0.1",
			RELEASE_EVIDENCE_COMPLIANCE: compliance(0),
		});
		expect([taken.status, taken.stderr]).toEqual([0, ""]);
		expect(JSON.parse(readFileSync(join(kept, "manifest.json"), "utf8"))).toMatchObject({
			tag: { name: "v1.0.1" },
			run: { repository, id: 7, branch: "release/1.0.1", tested: { commit: head } },
			artifacts: ["compliance", "evidence-area-0-1"],
		});
		expect(readFileSync(join(kept, "ci", "evidence-area-0-1", "a.json"), "utf8")).toBe(
			report(head),
		);
		expect(existsSync(join(kept, "ci", "compliance", "compliance.json"))).toBe(true);
	});
});
