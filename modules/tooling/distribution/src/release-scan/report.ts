/**
 * The report of what Trivy found in the release's lists: per list, the count of each severity, and
 * the critical and high findings that have a fix; a list not scanned told as such, with why.
 */

/** One list's scan: Trivy's JSON as it wrote it, or why there is none. */
export type Scanned =
	| { readonly list: string; readonly output: string }
	| { readonly list: string; readonly notScanned: string };

/** A finding, as the report keeps it. */
export interface Finding {
	readonly id: string;
	readonly pkg: string;
	readonly installed: string;
	readonly fixed: string;
	readonly severity: string;
}

/** A list read: how many packages Trivy read in it and its findings, or why it is told as not scanned. */
export type Read =
	| {
			readonly list: string;
			readonly packages: number;
			/** Packages read per Trivy's class of result (`os-pkgs`, `lang-pkgs`). */
			readonly classes: Readonly<Record<string, number>>;
			readonly findings: readonly Finding[];
	  }
	| { readonly list: string; readonly notScanned: string };

export const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;

/**
 * The findings in Trivy's JSON, each once by id and package. Output that is not Trivy's report, or a
 * report of no package read (a list whose components Trivy did not recognise), is not scanned.
 */
export function readScan(scanned: Scanned): Read {
	if ("notScanned" in scanned) return scanned;
	let report: unknown;
	try {
		report = JSON.parse(scanned.output);
	} catch {
		return { list: scanned.list, notScanned: "Trivy's output is not JSON" };
	}
	const results = (report as { Results?: unknown } | null)?.Results;
	if (typeof report !== "object" || report === null || !("SchemaVersion" in report))
		return { list: scanned.list, notScanned: "Trivy's output is not its report" };
	if (results !== undefined && !Array.isArray(results))
		return { list: scanned.list, notScanned: "Trivy's report holds no list of results" };
	const each = (results ?? []) as {
		Class?: unknown;
		Packages?: unknown;
		Vulnerabilities?: unknown;
	}[];
	const formed = (v: unknown) => v === undefined || v === null || Array.isArray(v);
	if (each.some((r) => !formed(r.Packages) || !formed(r.Vulnerabilities)))
		return {
			list: scanned.list,
			notScanned: "Trivy's report holds a result that is not its form",
		};
	const text = (v: unknown) => (typeof v === "string" ? v : "");
	const record = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;
	const named = (v: unknown, key: string) =>
		record(v) && typeof v[key] === "string" && v[key] !== "";
	// A package names itself and, where Trivy writes one, its version as text; a vulnerability its id and package.
	const packageFormed = (p: unknown) =>
		named(p, "Name") && record(p) && (p.Version === undefined || typeof p.Version === "string");
	const vulnerabilityFormed = (v: unknown) => named(v, "VulnerabilityID") && named(v, "PkgName");
	if (
		each.some(
			(r) =>
				(Array.isArray(r.Packages) && !r.Packages.every(packageFormed)) ||
				(Array.isArray(r.Vulnerabilities) && !r.Vulnerabilities.every(vulnerabilityFormed)),
		)
	)
		return {
			list: scanned.list,
			notScanned: "Trivy's report holds a record that is not its form",
		};
	const classes: Record<string, number> = {};
	for (const r of each) {
		const n = Array.isArray(r.Packages) ? r.Packages.length : 0;
		const kind = text(r.Class) || "unclassed";
		classes[kind] = (classes[kind] ?? 0) + n;
	}
	const read = Object.values(classes).reduce((n, c) => n + c, 0);
	if (read === 0) return { list: scanned.list, notScanned: "Trivy read no packages" };
	const all = each.flatMap((r) =>
		Array.isArray(r.Vulnerabilities) ? (r.Vulnerabilities as Record<string, unknown>[]) : [],
	);
	const findings = new Map<string, Finding>();
	for (const v of all) {
		const finding: Finding = {
			id: text(v.VulnerabilityID),
			pkg: text(v.PkgName),
			installed: text(v.InstalledVersion),
			fixed: text(v.FixedVersion),
			severity: (severities as readonly string[]).includes(text(v.Severity))
				? text(v.Severity)
				: "UNKNOWN",
		};
		findings.set(`${finding.id} ${finding.pkg} ${finding.installed}`, finding);
	}
	return { list: scanned.list, packages: read, classes, findings: [...findings.values()] };
}

/** The report in Markdown: what was scanned with what, the counts, and the fixable critical and high findings. */
export function reportOf(read: readonly Read[], trivy: string, version: string): string {
	const counts = read.map((r) =>
		"notScanned" in r
			? `| \`${r.list}\` | not scanned: ${cell(r.notScanned)} ||||||`
			: `| \`${r.list}\` | ${r.packages} | ${severities.map((s) => r.findings.filter((f) => f.severity === s).length).join(" | ")} |`,
	);
	const fixable = read.flatMap((r) =>
		"notScanned" in r
			? []
			: r.findings
					.filter((f) => (f.severity === "CRITICAL" || f.severity === "HIGH") && f.fixed !== "")
					.toSorted((a, b) => rank(a) - rank(b) || a.pkg.localeCompare(b.pkg))
					.map(
						(f) =>
							`| \`${r.list}\` | ${f.severity} | ${cell(f.pkg)} | ${cell(f.installed)} | ${cell(f.fixed)} | ${cell(f.id)} |`,
					),
	);
	return `# Known vulnerabilities in what auth-provider${version === "" ? "" : ` ${version}`} ships

Found by Trivy (\`${trivy}\`) in the lists the release made (\`release-sbom\`), against its vulnerability database on the day of the release run. A report only: nothing here stopped or delayed the release. Each list's full findings are in \`<list>.trivy.json\` beside this file.

| List | packages read | ${severities.map((s) => s.toLowerCase()).join(" | ")} |
|---|---|---|---|---|---|---|
${counts.join("\n")}

## Critical and high with a fix

${fixable.length === 0 ? "None." : `| List | Severity | Package | Installed | Fixed in | ID |\n|---|---|---|---|---|---|\n${fixable.join("\n")}`}
`;
}

export const rank = (f: Finding) => (f.severity === "CRITICAL" ? 0 : 1);
/** Text kept to one table cell. */
export const cell = (s: string) => s.replace(/\s+/g, " ").replaceAll("|", "\\|").trim();
/** A failure's reason as one short line: the last its tool wrote. */
export const reasonOf = (told: string) =>
	(
		told
			.trim()
			.split("\n")
			.filter((l) => l.trim() !== "")
			.at(-1) ?? "no reason given"
	).slice(0, 300);
