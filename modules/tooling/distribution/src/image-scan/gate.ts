/**
 * The gate on a generated app's image: Trivy asked for the critical and high vulnerabilities with a
 * fix in its OS and Node packages, its answer judged, beside whether its Node is behind a security
 * release. It passes only where Trivy ended clean, its report read OS and Node packages and holds no
 * finding, and the image's Node is current.
 */
import { cell, rank, readScan, reasonOf } from "../release-scan/report.ts";
import type { NodeChecked } from "./node.ts";

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

/** The class Trivy gives each kind of package the gate requires, by the name the report tells. */
const required = { OS: "os-pkgs", Node: "lang-pkgs" } as const;

/** Trivy's part of the verdict: whether it passed, and its lines. */
function scanned(ran: Ran): { readonly passed: boolean; readonly lines: string } {
	const read = readScan({ list: "image", output: ran.stdout });
	const notScanned = (why: string) => ({
		passed: false,
		lines: `Not scanned: ${cell(why)}. Nothing is known of the image's packages.`,
	});
	// Output that is no report of Trivy's is told by what Trivy wrote last, when it failed.
	const reported = (() => {
		try {
			const r: unknown = JSON.parse(ran.stdout);
			return typeof r === "object" && r !== null && "SchemaVersion" in r;
		} catch {
			return false;
		}
	})();
	if ("notScanned" in read)
		return notScanned(ran.status !== 0 && !reported ? reasonOf(ran.stderr) : read.notScanned);
	const missing = Object.entries(required).find(([, c]) => (read.classes[c] ?? 0) === 0);
	if (missing) return notScanned(`Trivy read no ${missing[0]} packages`);
	if (read.findings.length === 0 && ran.status !== 0) return notScanned(reasonOf(ran.stderr));
	const counted = `${read.classes[required.OS]} OS packages and ${read.classes[required.Node]} Node packages read`;
	if (read.findings.length === 0)
		return { passed: true, lines: `No critical or high vulnerability with a fix, ${counted}.` };
	const rows = read.findings
		.toSorted((a, b) => rank(a) - rank(b) || a.pkg.localeCompare(b.pkg) || a.id.localeCompare(b.id))
		.map(
			(f) =>
				`| ${f.severity} | ${cell(f.pkg)} | ${cell(f.installed)} | ${cell(f.fixed)} | ${cell(f.id)} |`,
		);
	return {
		passed: false,
		lines: `${read.findings.length} critical or high vulnerabilities with a fix, ${counted}.\n\n| Severity | Package | Installed | Fixed in | ID |\n|---|---|---|---|---|\n${rows.join("\n")}`,
	};
}

/** The Node check's line of the verdict. */
const nodeLine = (node: NodeChecked) =>
	"notChecked" in node
		? `Node not checked: ${cell(node.notChecked)}.`
		: node.behind
			? `Node ${node.version} is behind ${node.newest}, a security release: move app-output's \`nodeImage\` to the ${node.minor} minor (\`node:${node.minor}-alpine\`).`
			: `Node ${node.version}: no security release of its major is newer.`;

/** The scan judged: findings fail it, a scan that cannot be read as one, and a Node not current. */
export function verdictOf(
	ran: Ran,
	node: NodeChecked,
	about: { readonly trivy: string; readonly app: string },
): Verdict {
	const scan = scanned(ran);
	const passed = scan.passed && "behind" in node && !node.behind;
	return {
		passed,
		report: `# Known vulnerabilities in a generated app's image

${about.app}, its image built as its guide says (\`docker build --pull --no-cache-filter=runtime\`), scanned by Trivy (\`${about.trivy}\`) in its OS and Node packages, and its Node held to Node's security releases. A critical or high vulnerability that has a fix, or a security release of its Node's major newer than it, fails the scan.

**${passed ? "Passed" : "Failed"}.**

${nodeLine(node)}

${scan.lines}
`,
	};
}
