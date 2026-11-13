import { expect, it } from "vitest";
import { trivyArguments, verdictOf } from "../gate.ts";
import type { NodeChecked } from "../node.ts";

const about = { trivy: "aquasec/trivy:1@sha256:abc", app: "the `full` app" };
const current: NodeChecked = { behind: false, version: "v24.22.3" };
const packages = (n: number) => Array.from({ length: n }, (_, i) => ({ Name: `p${i}` }));
const os = (n = 3, Vulnerabilities: unknown = []) => ({
	Target: "image.tar (alpine 3.24.4)",
	Class: "os-pkgs",
	Packages: packages(n),
	Vulnerabilities,
});
const lang = (n = 2, Vulnerabilities: unknown = []) => ({
	Target: "Node.js",
	Class: "lang-pkgs",
	Packages: packages(n),
	Vulnerabilities,
});
const report = (...results: unknown[]) => JSON.stringify({ SchemaVersion: 2, Results: results });
const vulnerability = (id: string, pkg: string, severity: string) => ({
	VulnerabilityID: id,
	PkgName: pkg,
	InstalledVersion: "1.0.0",
	FixedVersion: "1.0.1",
	Severity: severity,
});
const clean = { status: 0, stdout: report(os(), lang()), stderr: "" };

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

it("passes a scan that read OS and Node packages and found nothing, its Node current", () => {
	const verdict = verdictOf(clean, current, about);
	expect(verdict.passed).toBe(true);
	expect(verdict.report).toContain("**Passed.**");
	expect(verdict.report).toContain("3 OS packages and 2 Node packages read");
	expect(verdict.report).toContain("Node v24.22.3: no security release of its major is newer.");
	expect(verdict.report).toContain(about.trivy);
	expect(verdict.report).toContain(about.app);
});

it("fails on findings, each told once, critical first", () => {
	const high = vulnerability("CVE-2", "zlib", "HIGH");
	const critical = vulnerability("CVE-1", "openssl", "CRITICAL");
	const verdict = verdictOf(
		{ status: 1, stdout: report(os(3, [high, critical, high]), lang()), stderr: "" },
		current,
		about,
	);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain("**Failed.**");
	const rows = verdict.report
		.split("\n")
		.filter((l) => l.startsWith("| CRITICAL") || l.startsWith("| HIGH"));
	expect(rows).toEqual([
		"| CRITICAL | openssl | 1.0.0 | 1.0.1 | CVE-1 |",
		"| HIGH | zlib | 1.0.0 | 1.0.1 | CVE-2 |",
	]);
});

it("fails on a finding even where Trivy's exit said nothing was found", () => {
	const stdout = report(os(), lang(2, [vulnerability("CVE-1", "a", "HIGH")]));
	expect(verdictOf({ status: 0, stdout, stderr: "" }, current, about).passed).toBe(false);
});

it("fails a scan Trivy could not make, as not scanned with its last line, never as clean", () => {
	const verdict = verdictOf(
		{ status: 1, stdout: "", stderr: "INFO downloading\nFATAL db: 429 too many requests\n" },
		current,
		about,
	);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain("Not scanned: FATAL db: 429 too many requests");
});

it("fails a report that read no OS package, or no Node package, as not scanned", () => {
	for (const [stdout, missing] of [
		[report(lang()), "OS"],
		[report(os(), lang(0)), "Node"],
	] as const) {
		const verdict = verdictOf({ status: 0, stdout, stderr: "" }, current, about);
		expect(verdict.passed).toBe(false);
		expect(verdict.report).toContain(`Not scanned: Trivy read no ${missing} packages`);
	}
});

it("fails a report whose vulnerabilities are not a list, as not scanned", () => {
	const verdict = verdictOf(
		{ status: 1, stdout: report(os(3, {}), lang()), stderr: "" },
		current,
		about,
	);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain(
		"Not scanned: Trivy's report holds a result that is not its form",
	);
});

it("fails a report with no finding where Trivy did not end clean", () => {
	const verdict = verdictOf({ ...clean, status: 2, stderr: "FATAL killed\n" }, current, about);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain("Not scanned: FATAL killed");
});

it("fails a clean scan whose Node is behind a security release, naming the minor to move to", () => {
	const verdict = verdictOf(
		clean,
		{ behind: true, version: "v24.22.3", newest: "v24.23.1", minor: "24.23" },
		about,
	);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain(
		"Node v24.22.3 is behind v24.23.1, a security release: move app-output's `nodeImage` to the 24.23 minor (`node:24.23-alpine`).",
	);
});

it("fails a clean scan whose Node could not be checked, never as passed", () => {
	const verdict = verdictOf(clean, { notChecked: "fetch failed" }, about);
	expect(verdict.passed).toBe(false);
	expect(verdict.report).toContain("Node not checked: fetch failed.");
});
