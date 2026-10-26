import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { cacheProblems, evidenceRuns, releaseRun } from "../caches.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..", "..", "..");
const repository = (path: string) => readFileSync(join(root, path), "utf8");

describe("this repository's workflows", () => {
	it("restore no cache in a run whose evidence a release may take", () => {
		for (const run of evidenceRuns("0.19.1")) {
			expect(cacheProblems(".github/workflows/ci.yml", run, repository)).toEqual([]);
		}
	});

	it("restore no cache in the release's own run, the API site's workflow it calls included", () => {
		expect(
			cacheProblems(".github/workflows/release.yml", releaseRun("0.19.1"), repository),
		).toEqual([]);
	});

	it("still restore caches in other runs, so the check is not passing by reading nothing", () => {
		const develop = { event_name: "push", ref: "refs/heads/develop", base_ref: "" };
		expect(cacheProblems(".github/workflows/ci.yml", develop, repository).length).toBeGreaterThan(
			0,
		);
	});
});

const evidence =
	"(github.event_name == 'push' && startsWith(github.ref, 'refs/heads/release/')) || (github.event_name == 'pull_request' && github.base_ref == 'main')";
const [push] = evidenceRuns("0.19.1");
const run = push as NonNullable<typeof push>;

/** The problems of one job's steps, written as YAML, in a push to the release branch. */
const ofSteps = (steps: string, more: Record<string, string> = {}) => {
	const files: Record<string, string> = {
		"w.yml": `jobs:\n  j:\n    runs-on: x\n    steps:\n${steps}`,
		...more,
	};
	return cacheProblems("w.yml", run, (path) => {
		const text = files[path];
		if (text === undefined) throw new Error(`no ${path}`);
		return text;
	});
};

describe("cacheProblems", () => {
	it("refuses an action it does not know, or one at a ref not taken", () => {
		expect(ofSteps("      - uses: someone/thing@v1\n")).toEqual([
			expect.stringContaining("an action this check does not know"),
		]);
		expect(ofSteps("      - uses: actions/checkout@v3\n")).toEqual([
			expect.stringContaining("a ref not taken"),
		]);
		expect(ofSteps("      - uses: ./.github/actions/local\n")).toEqual([
			expect.stringContaining("an action this check does not know"),
		]);
		expect(ofSteps("      - uses: docker://alpine:3\n")).toEqual([
			expect.stringContaining("an action this check does not know"),
		]);
	});

	it("refuses a cache step that may run, and passes one turned off in the run", () => {
		expect(ofSteps("      - uses: actions/cache@v4\n")).toEqual([
			expect.stringContaining("restores a cache"),
		]);
		expect(ofSteps(`      - uses: actions/cache@v4\n        if: \${{ !(${evidence}) }}\n`)).toEqual(
			[],
		);
		expect(
			ofSteps("      - uses: actions/cache/restore@v4\n        if: matrix.node == '24'\n"),
		).toEqual([expect.stringContaining("restores a cache")]);
	});

	it("reads setup-go's cache as on unless it is written off", () => {
		expect(ofSteps("      - uses: actions/setup-go@v5\n")).toEqual([
			expect.stringContaining("its cache is on"),
		]);
		expect(
			ofSteps("      - uses: actions/setup-go@v5\n        with:\n          cache: false\n"),
		).toEqual([]);
		expect(
			ofSteps(
				`      - uses: actions/setup-go@v5\n        with:\n          cache: \${{ !(${evidence}) }}\n`,
			),
		).toEqual([]);
	});

	it("reads pnpm's cache and install, whether written plainly or as an expression", () => {
		expect(ofSteps("      - uses: pnpm/action-setup@v4\n")).toEqual([]);
		expect(
			ofSteps("      - uses: pnpm/action-setup@v4\n        with:\n          cache: true\n"),
		).toEqual([expect.stringContaining("its cache is on")]);
		expect(
			ofSteps(
				"      - uses: pnpm/action-setup@v4\n        with:\n          cache: ${{ github.event_name == 'push' }}\n",
			),
		).toEqual([expect.stringContaining("its cache is on")]);
		expect(
			ofSteps("      - uses: pnpm/action-setup@v4\n        with:\n          run_install: true\n"),
		).toEqual([expect.stringContaining("its run_install is on")]);
	});

	it("reads setup-java's cache as GitHub does, `cond && '' || x` being x", () => {
		expect(
			ofSteps(
				`      - uses: actions/setup-java@v4\n        with:\n          cache: \${{ !(${evidence}) && 'maven' || '' }}\n`,
			),
		).toEqual([]);
		expect(
			ofSteps(
				`      - uses: actions/setup-java@v4\n        with:\n          cache: \${{ (${evidence}) && '' || 'maven' }}\n`,
			),
		).toEqual([expect.stringContaining('its cache is "maven"')]);
	});

	it("refuses a download that reaches another run", () => {
		expect(
			ofSteps("      - uses: actions/download-artifact@v4\n        with:\n          run-id: 1\n"),
		).toEqual([expect.stringContaining("reaches past this run")]);
	});

	it("passes over a job or step decided not to run, but not an action it does not know there", () => {
		expect(
			ofSteps("      - uses: actions/cache@v4\n        if: github.event_name == 'schedule'\n"),
		).toEqual([]);
		expect(
			ofSteps("      - uses: someone/thing@v1\n        if: github.event_name == 'schedule'\n"),
		).toHaveLength(1);
	});

	it("follows a workflow of this tree a job calls, refuses one outside it and a loop", () => {
		const calls = (target: string) => `jobs:\n  c:\n    uses: ${target}\n`;
		const cached = "jobs:\n  k:\n    runs-on: x\n    steps:\n      - uses: actions/cache@v4\n";
		const files: Record<string, string> = {
			"a.yml": calls("./.github/workflows/b.yml"),
			".github/workflows/b.yml": cached,
			"o.yml": calls("someone/repo/.github/workflows/x.yml@v1"),
			".github/workflows/l1.yml": calls("./.github/workflows/l2.yml"),
			".github/workflows/l2.yml": calls("./.github/workflows/l1.yml"),
		};
		const read = (path: string) => files[path] as string;
		expect(cacheProblems("a.yml", run, read)).toEqual([
			expect.stringMatching(/^\.github\/workflows\/b\.yml: job k.*restores a cache/),
		]);
		expect(cacheProblems("o.yml", run, read)).toEqual([
			expect.stringContaining("a workflow outside this tree"),
		]);
		expect(cacheProblems(".github/workflows/l1.yml", run, read)).toEqual([
			expect.stringContaining("in a loop"),
		]);
	});
});
