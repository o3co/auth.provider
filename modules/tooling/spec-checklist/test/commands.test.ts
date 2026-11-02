import { spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const main = join(import.meta.dirname, "..", "src", "main.ts");
/** Runs a command over a checklist of one broken file, writing into `out`. */
const run = (args: string[], out: string) => {
	const dir = mkdtempSync(join(tmpdir(), "spec-checklist-broken-"));
	writeFileSync(
		join(dir, "rfc9999.md"),
		"# RFC 9999\n\n## 2 Two\n\n- **rfc9999-2-a** MUST: x.\n  faults: F\n",
	);
	return spawnSync(process.execPath, [main, ...args], {
		encoding: "utf8",
		env: { ...process.env, SPEC_CHECKLIST_DIR: dir, SPEC_CHECKLIST_REPORT_DIR: out },
	});
};

describe("the commands that write", () => {
	it("write nothing, and fail, where the checklist has a finding", () => {
		const out = mkdtempSync(join(tmpdir(), "spec-checklist-out-"));
		writeFileSync(join(out, "README.md"), "kept");
		const report = run(["report"], out);
		expect(report.status).toBe(1);
		expect(report.stdout).toMatch(/a faults line is a guarantee's alone/);
		expect(readdirSync(out)).toEqual(["README.md"]);
		expect(readFileSync(join(out, "README.md"), "utf8")).toBe("kept");
		const reports = join(out, "reports");
		mkdirSync(reports);
		const compliance = run(["compliance", reports, "--release"], out);
		expect(compliance.status).toBe(1);
		expect(compliance.stdout).toMatch(/a faults line is a guarantee's alone/);
		expect(existsSync(join(reports, "compliance.json"))).toBe(false);
		// Each command reads the whole workspace's tests before it refuses.
	}, 30_000);
});
