import { expect, it } from "vitest";
import { readScan, reportOf } from "../report.ts";

const trivy = (vulns: Record<string, string>[]) =>
	JSON.stringify({
		SchemaVersion: 2,
		Results: [{ Target: "app", Vulnerabilities: vulns }, { Target: "empty" }],
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
		findings: [
			{ id: "CVE-1", pkg: "a", installed: "1.0.0", fixed: "1.0.1", severity: "HIGH" },
			{ id: "CVE-2", pkg: "b", installed: "1.0.0", fixed: "", severity: "UNKNOWN" },
		],
	});
	// A report with no results is a list with no findings.
	expect(readScan({ list: "x", output: JSON.stringify({ SchemaVersion: 2 }) })).toEqual({
		list: "x",
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
	expect(report).toContain("| `app.cdx.json` | 2 | 1 | 0 | 1 | 0 |");
	expect(report).toContain("| `image.cdx.json` | not scanned: timed out \\| twice |||||");
	const fixable = report.split("## Critical and high with a fix")[1] ?? "";
	expect(fixable.match(/CVE-\d/g)).toEqual(["CVE-5", "CVE-3"]);
	expect(reportOf([{ list: "a", findings: [] }], "t", "v")).toContain("with a fix\n\nNone.\n");
	// No version known: the title reads whole.
	expect(reportOf([], "t", "")).toContain("# Known vulnerabilities in what auth-provider ships\n");
});
