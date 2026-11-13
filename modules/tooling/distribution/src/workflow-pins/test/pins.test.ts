import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { pinFiles, pinProblems } from "../pins.ts";

const repository = join(import.meta.dirname, "..", "..", "..", "..", "..", "..");
const sha = "11d5960a326750d5838078e36cf38b85af677262";
const image = `alpine:3@sha256:${"a".repeat(64)}`;

it("holds every workflow and action of this repository pinned", () => {
	const files = pinFiles(repository);
	expect(files).toContain(join(".github", "workflows", "ci.yml"));
	expect(files).toContain(join(".github", "workflows", "release.yml"));
	expect(files.flatMap((f) => pinProblems(f, readFileSync(join(repository, f), "utf8")))).toEqual(
		[],
	);
});

describe("pinFiles", () => {
	const root = mkdtempSync(join(tmpdir(), "workflow-pins-"));
	afterAll(() => rmSync(root, { recursive: true, force: true }));
	const write = (path: string) => {
		mkdirSync(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), "on: push\n");
	};

	it("finds the files by the rule: workflows of either extension, and the actions held, nothing else", () => {
		for (const p of [
			".github/workflows/a.yml",
			".github/workflows/b.yaml",
			".github/workflows/notes.md",
			".github/actions/x/action.yml",
			".github/actions/y/action.yaml",
			".github/actions/y/other.yml",
			".github/dependabot.yml",
		])
			write(p);
		expect(pinFiles(root)).toEqual(
			[
				".github/actions/x/action.yml",
				".github/actions/y/action.yaml",
				".github/workflows/a.yml",
				".github/workflows/b.yaml",
			].map((p) => join(...p.split("/"))),
		);
	});

	it("finds none where there is no .github", () => {
		expect(pinFiles(join(root, "nowhere"))).toEqual([]);
	});
});

describe("pinProblems", () => {
	const job = (body: string) => pinProblems("w.yml", `on: push\njobs:\n  j:\n${body}`);
	const step = (uses: string) => job(`    runs-on: x\n    steps:\n      - uses: ${uses}\n`);

	it("takes a step's action at a full commit with its version in a comment, and this repository's own", () => {
		expect(step(`actions/checkout@${sha} # v4.4.0`)).toEqual([]);
		expect(step("./.github/actions/x")).toEqual([]);
	});

	it("refuses a tag, a short commit, a pin with no version comment, and an expression", () => {
		expect(step("actions/checkout@v4")).toEqual([
			"w.yml: jobs.j.steps[0].uses: actions/checkout@v4 is not pinned to a full commit",
		]);
		expect(step("actions/checkout@11d5960 # v4.4.0")).toHaveLength(1);
		expect(step("actions/checkout")).toHaveLength(1);
		expect(step(`actions/checkout@${sha}`)).toEqual([
			`w.yml: jobs.j.steps[0].uses: actions/checkout@${sha} names no version in its comment (# v…)`,
		]);
		expect(step(`actions/checkout@${sha} # latest`)).toHaveLength(1);
		// An expression, as GitHub writes one.
		expect(step(`actions/checkout@${"$"}{{ env.REF }}`)).toEqual([
			expect.stringContaining("is an expression"),
		]);
	});

	it("holds a job calling another repository's workflow to a commit", () => {
		expect(job(`    uses: o/r/.github/workflows/x.yml@${sha} # v2.7.0\n`)).toEqual([]);
		expect(job("    uses: o/r/.github/workflows/x.yml@main\n")).toEqual([
			"w.yml: jobs.j.uses: o/r/.github/workflows/x.yml@main is not pinned to a full commit",
		]);
	});

	it("holds docker:// and every image a job runs to its digest", () => {
		expect(step(`docker://${image}`)).toEqual([]);
		expect(step("docker://alpine:3")).toEqual([
			expect.stringContaining("not pinned to an image digest"),
		]);
		expect(job(`    container: ${image}\n`)).toEqual([]);
		expect(job("    container: alpine:3\n")).toEqual([
			"w.yml: jobs.j.container: alpine:3 is not pinned to an image digest (@sha256:)",
		]);
		expect(job("    container:\n      image: alpine:3\n")).toEqual([
			"w.yml: jobs.j.container.image: alpine:3 is not pinned to an image digest (@sha256:)",
		]);
		expect(job(`    container:\n      image: ${image}\n`)).toEqual([]);
		expect(job("    services:\n      redis:\n        image: redis:7\n")).toEqual([
			"w.yml: jobs.j.services.redis.image: redis:7 is not pinned to an image digest (@sha256:)",
		]);
	});

	it("reads an action this repository holds: a composite's steps and a Docker action's image", () => {
		const action = (runs: string) => pinProblems("action.yml", `name: x\nruns:\n${runs}`);
		expect(action("  using: composite\n  steps:\n    - uses: o/r@v1\n")).toEqual([
			"action.yml: runs.steps[0].uses: o/r@v1 is not pinned to a full commit",
		]);
		expect(action("  using: docker\n  image: docker://alpine:3\n")).toHaveLength(1);
		expect(action("  using: docker\n  image: Dockerfile\n")).toEqual([]);
	});

	it("refuses a file that is not YAML", () => {
		expect(pinProblems("w.yml", "jobs: [\n")).toEqual([expect.stringContaining("not YAML")]);
	});
});
