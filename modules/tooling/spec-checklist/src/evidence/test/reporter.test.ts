import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import type { EvidenceReport } from "../reporter.ts";

const fixture = join(import.meta.dirname, "fixtures", "evidence");
const root = join(import.meta.dirname, "..", "..", "..", "..", "..", "..");

it("writes a run's results, named by what ran them, even where tests fail or a file does not load", () => {
	const dir = mkdtempSync(join(tmpdir(), "spec-evidence-"));
	const ran = spawnSync(
		"pnpm",
		["exec", "vitest", "run", "--config", join(fixture, "vitest.config.ts")],
		{
			cwd: root,
			encoding: "utf8",
			env: {
				...process.env,
				SPEC_EVIDENCE_DIR: dir,
				GITHUB_SHA: "c1",
				GITHUB_RUN_ID: "r1",
				GITHUB_RUN_ATTEMPT: "2",
				GITHUB_JOB: "checks",
				CONFORMANCE_PATTERN: "",
			},
		},
	);
	expect(ran.status).not.toBe(0);
	const [file] = readdirSync(dir);
	const report = JSON.parse(readFileSync(join(dir, file ?? ""), "utf8")) as EvidenceReport;
	expect(report.identity).toEqual({
		commit: "c1",
		run: "r1",
		attempt: 2,
		job: "checks",
		entry: "modules/tooling/spec-checklist/src/evidence/test/fixtures/evidence",
		target: "new",
	});
	const at = "modules/tooling/spec-checklist/src/evidence/test/fixtures/evidence";
	expect(
		[...report.tests].sort(
			(a, b) => a.file.localeCompare(b.file) || a.names.join().localeCompare(b.names.join()),
		),
	).toEqual([
		{ file: `${at}/broken.sample.ts`, names: [], state: "failed" },
		{
			file: `${at}/runs.sample.ts`,
			names: ["a suite [rfc7009-2-a]", "fails [rfc7009-2-c]"],
			state: "failed",
		},
		{
			file: `${at}/runs.sample.ts`,
			names: ["a suite [rfc7009-2-a]", "is left out"],
			state: "skipped",
			note: "excused: adaptation",
		},
		{
			file: `${at}/runs.sample.ts`,
			names: ["a suite [rfc7009-2-a]", "passes [rfc7009-2-b]"],
			state: "passed",
		},
	]);
});

it("writes nothing without SPEC_EVIDENCE_DIR", () => {
	const ran = spawnSync(
		"pnpm",
		["exec", "vitest", "run", "--config", join(fixture, "vitest.config.ts")],
		{
			cwd: root,
			encoding: "utf8",
			env: { ...process.env, SPEC_EVIDENCE_DIR: "" },
		},
	);
	expect(ran.status).not.toBe(0);
});
