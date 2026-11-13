import { expect, it } from "vitest";
import { readScan, reportOf } from "../report.ts";

const trivy = (vulns: Record<string, string>[]) =>
	JSON.stringify({
		SchemaVersion: 2,
		Results: [
			{
				Target: "app",
				Class: "lang-pkgs",
				Packages: [{ Name: "a" }, { Name: "b" }],
				Vulnerabilities: vulns,
			},
			{ Target: "empty", Class: "os-pkgs", Packages: [{ Name: "c" }] },
		],
	});
const vuln = (id: string, pkg: string, severity: string, fixed = "") => ({
	VulnerabilityID: id,
	PkgName: pkg,
	InstalledVersion: "1.0.0",
	FixedVersion: fixed,
	Severity: severity,
});

it("reads each finding once by its id, package and installed version", () => {
	const read = readScan({
		list: "app.cdx.json",
		output: trivy([
			vuln("CVE-1", "a", "HIGH", "1.0.1"),
			vuln("CVE-1", "a", "HIGH", "1.0.1"),
			vuln("CVE-2", "b", "odd"),
		]),
	});
	expect(read).toEqual({
		list: "app.cdx.json",
		packages: 3,
		classes: { "lang-pkgs": 2, "os-pkgs": 1 },
		findings: [
			{ id: "CVE-1", pkg: "a", installed: "1.0.0", fixed: "1.0.1", severity: "HIGH" },
			{ id: "CVE-2", pkg: "b", installed: "1.0.0", fixed: "", severity: "UNKNOWN" },
		],
	});
	// Packages read and none vulnerable: a list with no findings.
	expect(readScan({ list: "x", output: trivy([]) })).toEqual({
		list: "x",
		packages: 3,
		classes: { "lang-pkgs": 2, "os-pkgs": 1 },
		findings: [],
	});
});

it("tells output that is not Trivy's report as not scanned, never as no findings", () => {
	expect(readScan({ list: "x", output: "FATAL boom" })).toEqual({
		list: "x",
		notScanned: "Trivy's output is not JSON",
	});
	expect(readScan({ list: "x", output: "[]" })).toEqual({
		list: "x",
		notScanned: "Trivy's output is not its report",
	});
	expect(readScan({ list: "x", output: '{"SchemaVersion":2,"Results":{}}' })).toEqual({
		list: "x",
		notScanned: "Trivy's report holds no list of results",
	});
	// A report of no package read, with no results or with results holding none, is not a clean list.
	for (const output of [
		JSON.stringify({ SchemaVersion: 2 }),
		JSON.stringify({ SchemaVersion: 2, Results: [{ Target: "app", Packages: [] }] }),
	])
		expect(readScan({ list: "x", output })).toEqual({
			list: "x",
			notScanned: "Trivy read no packages",
		});
	// A result whose packages or vulnerabilities are no list is a report not read as Trivy writes it.
	for (const result of [
		{ Target: "app", Packages: [{ Name: "a" }], Vulnerabilities: {} },
		{ Target: "app", Packages: {} },
	])
		expect(
			readScan({ list: "x", output: JSON.stringify({ SchemaVersion: 2, Results: [result] }) }),
		).toEqual({ list: "x", notScanned: "Trivy's report holds a result that is not its form" });
	expect(readScan({ list: "x", notScanned: "no network" })).toEqual({
		list: "x",
		notScanned: "no network",
	});
});

it("writes the counts per list, a list not scanned with its reason, and the fixable critical and high", () => {
	const report = reportOf(
		[
			{
				list: "app.cdx.json",
				packages: 40,
				classes: { "lang-pkgs": 40 },
				findings: [
					{ id: "CVE-3", pkg: "z", installed: "1", fixed: "2", severity: "HIGH" },
					{ id: "CVE-4", pkg: "y", installed: "1", fixed: "", severity: "CRITICAL" },
					{ id: "CVE-5", pkg: "x", installed: "1", fixed: "3", severity: "CRITICAL" },
					{ id: "CVE-6", pkg: "w", installed: "1", fixed: "2", severity: "LOW" },
				],
			},
			{ list: "image.cdx.json", notScanned: "timed out | twice" },
		],
		"aquasec/trivy:1@sha256:00",
		"0.20.0",
	);
	expect(report).toContain("# Known vulnerabilities in what auth-provider 0.20.0 ships");
	expect(report).toContain("`aquasec/trivy:1@sha256:00`");
	expect(report).toContain("| `app.cdx.json` | 40 | 2 | 1 | 0 | 1 | 0 |");
	expect(report).toContain("| `image.cdx.json` | not scanned: timed out \\| twice ||||||");
	const fixable = report.split("## Critical and high with a fix")[1] ?? "";
	expect(fixable.match(/CVE-\d/g)).toEqual(["CVE-5", "CVE-3"]);
	expect(
		reportOf([{ list: "a", packages: 1, classes: { "lang-pkgs": 1 }, findings: [] }], "t", "v"),
	).toContain("with a fix\n\nNone.\n");
	// No version known: the title reads whole.
	expect(reportOf([], "t", "")).toContain("# Known vulnerabilities in what auth-provider ships\n");
});
