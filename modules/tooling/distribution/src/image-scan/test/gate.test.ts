import { expect, it } from "vitest";
import { trivyArguments, verdictOf } from "../gate.ts";

const about = { trivy: "aquasec/trivy:1@sha256:abc", app: "the `full` app" };
const report = (vulnerabilities: readonly Record<string, string>[], packages = 3) =>
	JSON.stringify({
		SchemaVersion: 2,
		Results: [
			{
				Target: "app (alpine 3.22.2)",
				Packages: Array.from({ length: packages }, (_, i) => ({ Name: `p${i}` })),
				Vulnerabilities: vulnerabilities,
			},
		],
	});
const vulnerability = (id: string, pkg: string, severity: string) => ({
	VulnerabilityID: id,
	PkgName: pkg,
	InstalledVersion: "1.0.0",
	FixedVersion: "1.0.1",
	Severity: severity,
});

it("runs the pinned Trivy on the saved image read-only, failing on a critical or high finding with a fix, OS and Node packages alike", () => {
	const args = trivyArguments({
		trivy: about.trivy,
		databases: ["ghcr.io/a/db:2", "public.ecr.aws/a/db:2"],
		dir: "/s/saved",
		file: "image.tar",
	});
	expect(args).toEqual([
		"run",
		"--rm",
		"-v",
		"/s/saved:/in:ro",
		about.trivy,
		"image",
		"--input",
		"/in/image.tar",
		"--scanners",
		"vuln",
		"--pkg-types",
		"os,library",
		"--severity",
		"HIGH,CRITICAL",
		"--ignore-unfixed",
		"--exit-code",
		"1",
		"--list-all-pkgs",
		"--format",
		"json",
		"--timeout",
		"10m",
		"--db-repository",
		"ghcr.io/a/db:2,public.ecr.aws/a/db:2",
	]);
	// No setting or token of the run passed in.
	expect(args.join(" ")).not.toMatch(/(^| )(-e|--env|--env-file)( |=)/);
});

it("passes a scan that read packages and found nothing", () => {
	const verdict = verdictOf({ status: 0, stdout: report([]), stderr: "" }, about);
	expect(verdict.passed).toBe(true);
	expect(verdict.report).toContain("Passed");
	expect(verdict.report).toContain("3 packages read");
	expect(verdict.report).toContain(about.trivy);
	expect(verdict.report).toContain(about.app);
});

it("fails on findings, each told once, critical first", () => {
	const high = vulnerability("CVE-2", "zlib", "HIGH");
	const critical = vulnerability("CVE-1", "openssl", "CRITICAL");
	const verdict = verdictOf(
		{ status: 1, stdout: report([high, critical, high]), stderr: "" },
		about,
	);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain("Failed");
	const rows = verdict.report
		.split("\n")
		.filter((l) => l.startsWith("| CRITICAL") || l.startsWith("| HIGH"));
	expect(rows).toEqual([
		"| CRITICAL | openssl | 1.0.0 | 1.0.1 | CVE-1 |",
		"| HIGH | zlib | 1.0.0 | 1.0.1 | CVE-2 |",
	]);
});

it("fails on a finding even where Trivy's exit said nothing was found", () => {
	const verdict = verdictOf(
		{ status: 0, stdout: report([vulnerability("CVE-1", "a", "HIGH")]), stderr: "" },
		about,
	);
	expect(verdict.passed).toBe(false);
});

it("fails a scan Trivy could not make, as not scanned with its last line, never as clean", () => {
	const verdict = verdictOf(
		{ status: 1, stdout: "", stderr: "INFO downloading\nFATAL db: 429 too many requests\n" },
		about,
	);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain("Not scanned: FATAL db: 429 too many requests");
});

it("fails a scan that read no package, never as clean", () => {
	const verdict = verdictOf({ status: 0, stdout: report([], 0), stderr: "" }, about);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain("Not scanned: Trivy read no packages");
});

it("fails a report with no finding where Trivy did not end clean", () => {
	const verdict = verdictOf({ status: 2, stdout: report([]), stderr: "FATAL killed\n" }, about);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain("Not scanned: FATAL killed");
});
