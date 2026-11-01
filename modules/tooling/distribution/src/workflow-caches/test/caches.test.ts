import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { cacheProblems, evidenceRun, mavenOffInEvidence, offInEvidence } from "../caches.ts";
import { inputOf, type RunContext } from "./expression.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..", "..", "..");
const repository = (path: string) => readFileSync(join(root, path), "utf8");
// The version this tree declares, so no condition naming another can pass for it.
const version = (JSON.parse(repository("package.json")) as { version: string }).version;

describe("this repository's workflows", () => {
	it("write every step that could restore a cache as set out, CI's and the release's, the API site's included", () => {
		expect(cacheProblems(".github/workflows/ci.yml", repository, "ci")).toEqual([]);
		expect(cacheProblems(".github/workflows/release.yml", repository, "release")).toEqual([]);
	});
});

describe("the conditions set out", () => {
	const runs: Record<string, RunContext> = {
		"a push to this version's release branch": {
			event_name: "push",
			ref: `refs/heads/release/${version}`,
			base_ref: "",
		},
		// A pull request's number, and so its ref, is not known: left out.
		"a pull request to main": { event_name: "pull_request", base_ref: "main" },
	};
	const others: RunContext[] = [
		{ event_name: "push", ref: "refs/heads/develop", base_ref: "" },
		{ event_name: "pull_request", base_ref: "develop" },
		{ event_name: "schedule", ref: "refs/heads/main", base_ref: "" },
	];

	it("turn a cache off in each run a release may take evidence from", () => {
		for (const run of Object.values(runs)) {
			expect(inputOf(offInEvidence, run)).toBe(false);
			expect(inputOf(mavenOffInEvidence, run)).toBe("");
		}
	});

	it("leave it on in the others", () => {
		for (const run of others) {
			expect(inputOf(offInEvidence, run)).toBe(true);
			expect(inputOf(mavenOffInEvidence, run)).toBe("maven");
		}
	});

	it("name those runs in CI's own words", () => {
		expect(evidenceRun).toContain("refs/heads/release/");
		expect(evidenceRun).toContain("github.base_ref == 'main'");
	});
});

/** The problems of one job's steps, written as YAML. */
const ofSteps = (
	steps: string,
	more: Record<string, string> = {},
	runs: "ci" | "release" = "ci",
) => {
	const files: Record<string, string> = {
		"w.yml": `jobs:\n  j:\n    runs-on: x\n    steps:\n${steps}`,
		...more,
	};
	return cacheProblems(
		"w.yml",
		(path) => {
			const text = files[path];
			if (text === undefined) throw new Error(`no ${path}`);
			return text;
		},
		runs,
	);
};
const step = (uses: string, inputs = "", condition = "") =>
	ofSteps(
		`      - uses: ${uses}\n${condition ? `        if: ${condition}\n` : ""}${inputs ? `        with:\n${inputs}` : ""}`,
	);

describe("cacheProblems", () => {
	it("refuses an action it does not know, or one at a ref not taken", () => {
		for (const uses of [
			"someone/thing@v1",
			"./.github/actions/local",
			"docker://alpine:3",
			"constructor@v1",
		]) {
			expect(step(uses)).toEqual([expect.stringContaining("an action this check does not know")]);
		}
		expect(step("actions/checkout@v3")).toEqual([expect.stringContaining("a ref not taken")]);
	});

	it("passes a cache step only with the condition set out, written exactly, nothing evaluated", () => {
		expect(step("actions/cache@v4", "", offInEvidence)).toEqual([]);
		for (const condition of [
			"",
			"github.event_name == 'schedule'",
			"${{ github.event_name == 'push' && !contains(github.ref, '9.9.9') }}",
			"\"'${{ github.event_name }}' == 'push'\"",
			"${{ null }}",
			offInEvidence.replace("!(", "! ("),
		]) {
			expect(step("actions/cache@v4", "", condition)).toEqual([
				expect.stringContaining("it restores a cache"),
			]);
			expect(step("actions/cache/restore@v4", "", condition)).toHaveLength(1);
		}
	});

	it("passes setup-go only with its cache written off, as it caches unless told not to", () => {
		expect(step("actions/setup-go@v5")).toEqual([expect.stringContaining("its cache is on")]);
		for (const ok of ["false", "'false'", offInEvidence]) {
			expect(step("actions/setup-go@v5", `          cache: ${ok}\n`)).toEqual([]);
		}
		for (const bad of ["true", "${{ false }}", "${{ github.event_name == 'schedule' }}"]) {
			expect(step("actions/setup-go@v5", `          cache: ${bad}\n`)).toEqual([
				expect.stringContaining("its cache is on"),
			]);
		}
	});

	it("passes setup-java's maven cache only as set out, and other setups' only left empty", () => {
		expect(step("actions/setup-java@v4")).toEqual([]);
		expect(step("actions/setup-java@v4", `          cache: ${mavenOffInEvidence}\n`)).toEqual([]);
		for (const bad of ["maven", `\${{ (${evidenceRun}) && '' || 'maven' }}`]) {
			expect(step("actions/setup-java@v4", `          cache: ${bad}\n`)).toEqual([
				expect.stringContaining("its cache must be"),
			]);
		}
		expect(step("actions/setup-node@v4", "          cache: pnpm\n")).toHaveLength(1);
		expect(step("actions/setup-python@v5", "          cache: pip\n")).toHaveLength(1);
		expect(step("actions/setup-python@v5", "          cache: ''\n")).toEqual([]);
	});

	it("passes pnpm's cache and install only left out or written false", () => {
		expect(step("pnpm/action-setup@v4")).toEqual([]);
		expect(step("pnpm/action-setup@v4", "          cache: false\n")).toEqual([]);
		for (const inputs of [
			"          cache: true\n",
			"          cache: ${{ false }}\n",
			"          run_install: true\n",
		]) {
			expect(step("pnpm/action-setup@v4", inputs)).toHaveLength(1);
		}
	});

	it("reads an input's name without regard to case, as GitHub does, and refuses one written twice", () => {
		expect(step("actions/setup-java@v4", "          CACHE: maven\n")).toHaveLength(1);
		expect(step("actions/setup-go@v5", "          Cache: true\n")).toHaveLength(1);
		for (const name of ["run-id", "Run-Id", "GitHub-Token"]) {
			expect(step("actions/download-artifact@v4", `          ${name}: x\n`)).toEqual([
				expect.stringContaining("reaches past this run"),
			]);
		}
		expect(
			step("actions/setup-go@v5", "          cache: false\n          CACHE: true\n"),
		).toContainEqual(expect.stringContaining("names CACHE twice"));
	});

	it("allows no cache at all in the release's own workflows, where the evidence condition holds", () => {
		const tag: RunContext = { event_name: "push", ref: `refs/tags/v${version}`, base_ref: "" };
		expect(inputOf(offInEvidence, tag)).toBe(true);
		const inRelease = (steps: string) => ofSteps(steps, {}, "release");
		expect(inRelease(`      - uses: actions/cache@v4\n        if: ${offInEvidence}\n`)).toEqual([
			expect.stringContaining("which the release never does"),
		]);
		expect(
			inRelease(
				`      - uses: actions/setup-go@v5\n        with:\n          cache: ${offInEvidence}\n`,
			),
		).toEqual([expect.stringContaining("as the release restores none")]);
		expect(
			inRelease("      - uses: actions/setup-go@v5\n        with:\n          cache: false\n"),
		).toEqual([]);
		expect(
			inRelease(
				`      - uses: actions/setup-java@v4\n        with:\n          cache: ${mavenOffInEvidence}\n`,
			),
		).toHaveLength(1);
		const files: Record<string, string> = {
			"r.yml": "jobs:\n  c:\n    uses: ./.github/workflows/s.yml\n",
			".github/workflows/s.yml": `jobs:\n  k:\n    runs-on: x\n    steps:\n      - uses: actions/cache@v4\n        if: ${offInEvidence}\n`,
		};
		expect(cacheProblems("r.yml", (p) => files[p] as string, "release")).toEqual([
			expect.stringMatching(/^\.github\/workflows\/s\.yml: job k.*which the release never does/),
		]);
		expect(cacheProblems("r.yml", (p) => files[p] as string, "ci")).toEqual([]);
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
		expect(cacheProblems("a.yml", read, "ci")).toEqual([
			expect.stringMatching(/^\.github\/workflows\/b\.yml: job k.*restores a cache/),
		]);
		expect(cacheProblems("o.yml", read, "ci")).toEqual([
			expect.stringContaining("a workflow outside this tree"),
		]);
		expect(cacheProblems(".github/workflows/l1.yml", read, "ci")).toEqual([
			expect.stringContaining("in a loop"),
		]);
	});
});
