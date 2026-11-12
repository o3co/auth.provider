/**
 * The gate on a generated app's image: Trivy asked for the critical and high vulnerabilities with a
 * fix in its OS and Node packages, and its answer judged. Only a report that read packages and holds
 * no finding, from a run that ended clean, passes.
 */
import { type Finding, readScan } from "../release-scan/report.ts";

/** The `docker run` arguments of the pinned Trivy on the image saved as `file` in `dir`, mounted read-only. */
export const trivyArguments = (p: {
	readonly trivy: string;
	readonly databases: readonly string[];
	readonly dir: string;
	readonly file: string;
}) => [
	"run",
	"--rm",
	"-v",
	`${p.dir}:/in:ro`,
	p.trivy,
	"image",
	"--input",
	`/in/${p.file}`,
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
	p.databases.join(","),
];

/** Trivy's run as it ended. */
export interface Ran {
	readonly status: number | null;
	readonly stdout: string;
	readonly stderr: string;
}

/** Whether the image passed, and the report in Markdown. */
export interface Verdict {
	readonly passed: boolean;
	readonly report: string;
}

/** The scan judged: findings fail it, and so does a scan that cannot be read as one. */
export function verdictOf(
	ran: Ran,
	about: { readonly trivy: string; readonly app: string },
): Verdict {
	const read = readScan({ list: "image", output: ran.stdout });
	const head = `# Known vulnerabilities in a generated app's image

${about.app}, its image built as its guide says (\`docker build --pull --no-cache-filter=runtime\`), scanned by Trivy (\`${about.trivy}\`) in its OS and Node packages. A critical or high vulnerability that has a fix fails the scan.
`;
	if ("notScanned" in read || (read.findings.length === 0 && ran.status !== 0)) {
		const why =
			ran.status !== 0 ? reasonOf(ran.stderr) : "notScanned" in read ? read.notScanned : "";
		return {
			passed: false,
			report: `${head}\n**Failed.** Not scanned: ${cell(why)}. Nothing is known of the image's packages.\n`,
		};
	}
	if (read.findings.length === 0)
		return {
			passed: true,
			report: `${head}\n**Passed.** No critical or high vulnerability with a fix, ${read.packages} packages read.\n`,
		};
	const rows = read.findings
		.toSorted((a, b) => rank(a) - rank(b) || a.pkg.localeCompare(b.pkg) || a.id.localeCompare(b.id))
		.map(
			(f) =>
				`| ${f.severity} | ${cell(f.pkg)} | ${cell(f.installed)} | ${cell(f.fixed)} | ${cell(f.id)} |`,
		);
	return {
		passed: false,
		report: `${head}\n**Failed.** ${read.findings.length} critical or high vulnerabilities with a fix, ${read.packages} packages read.\n\n| Severity | Package | Installed | Fixed in | ID |\n|---|---|---|---|---|\n${rows.join("\n")}\n`,
	};
}

const rank = (f: Finding) => (f.severity === "CRITICAL" ? 0 : 1);
/** A failure's reason as one short line: the last its tool wrote. */
const reasonOf = (told: string) =>
	(
		told
			.trim()
			.split("\n")
			.filter((l) => l.trim() !== "")
			.at(-1) ?? "no reason given"
	).slice(0, 300);
/** Text kept to one table cell. */
const cell = (s: string) => s.replace(/\s+/g, " ").replaceAll("|", "\\|").trim();
