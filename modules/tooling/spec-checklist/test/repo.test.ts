import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	expectedOf,
	readChecklist,
	repoFindings,
	repoRoot,
	reportDir,
	runsOf,
	updatedByOf,
	workspaceTests,
} from "../src/repo.ts";
import { reportFiles } from "../src/report.ts";

const checklist = readChecklist();
const workspace = workspaceTests(repoRoot);

describe("the checklist and the workspace's tests", () => {
	it("hold together: every file well formed, every ledger true to its items, every ID a test names an item in scope", () => {
		expect(repoFindings(checklist, workspace)).toEqual([]);
	});

	it("are what docs/compliance says, as `run report` writes it", () => {
		const files = reportFiles(checklist.specs, workspace.tests, updatedByOf(checklist));
		for (const [name, text] of files)
			expect(readFileSync(join(reportDir, name), "utf8"), name).toBe(text);
	});
});

describe("the runs a CI run must report", () => {
	const runs = [
		{ entry: "unit", kind: "unit" },
		{ entry: "integration", kind: "integration" },
		{ entry: "@mod/conformance-code", kind: "area", matrix: "@mod/conformance-code" },
		{ entry: "@mod/conformance-code@simple-web", kind: "pattern", matrix: "simple-web" },
		{ entry: "@mod/interop-oidf#basic", kind: "plan", matrix: "basic" },
		{ entry: "@mod/conformance-recipes", kind: "release", releaseOnly: true as const },
	];

	it("are every run, a release's own only where the run is a release's", () => {
		expect(expectedOf(runs, false).entries).toEqual(runs.slice(0, 5).map((r) => r.entry));
		expect(expectedOf(runs, true).entries).toEqual(runs.map((r) => r.entry));
	});

	it("tell an area's package and a harness's runs apart", () => {
		const expected = expectedOf(runs, false);
		expect([...expected.areas]).toEqual(["@mod/conformance-code"]);
		expect(expected.runsOf.get("@mod/interop-oidf")).toEqual(["@mod/interop-oidf#basic"]);
	});
});

describe("the workspace's runs", { timeout: 120_000 }, () => {
	it("are the root's, each area's, each pattern's and the recipes' release run, as the packages print them", () => {
		const runs = runsOf(repoRoot);
		expect(runs.slice(0, 2).map((r) => r.entry)).toEqual(["unit", "integration"]);
		expect(runs).toContainEqual({
			entry: "@mod/conformance-code",
			kind: "area",
			matrix: "@mod/conformance-code",
		});
		expect(runs).toContainEqual({
			entry: "@mod/conformance-code@full",
			kind: "pattern",
			matrix: "full",
		});
		expect(runs).toContainEqual({
			entry: "@mod/conformance-recipes",
			kind: "release",
			releaseOnly: true,
		});
	});
});
