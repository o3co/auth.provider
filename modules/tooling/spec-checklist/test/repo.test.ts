import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	expectedOf,
	readChecklist,
	repoFindings,
	repoRoot,
	reportDir,
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
	it("are the root's unit and integration runs and each conformance area's, beside what packages print", () => {
		const { entries, areas } = expectedOf(repoRoot);
		expect(entries.slice(0, 2)).toEqual(["unit", "integration"]);
		expect(areas.has("@mod/conformance-code")).toBe(true);
		expect(entries).toContain("@mod/conformance-code");
	});
});
