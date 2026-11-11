#!/usr/bin/env node
/**
 * After the release's lists are made: Trivy, its image pinned where this package names it
 * (`scan.json`), run on the lists of the reference image and of the operator's app, and the report
 * of what it found written into the directory named. A report only: a list that could not be scanned
 * is told as not scanned, and this exits 0 whatever Trivy found or failed at.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { docker, dockerWithin } from "@mod/docker-client";
import { endOf } from "../release-sbom/removal.ts";
import { type Read, readScan, reportOf, type Scanned } from "./report.ts";

const [given, into] = process.argv.slice(2);
if (!given || !into) {
	console.error(
		"release-scan: name the directory the lists are in, and the directory to write the report in",
	);
	process.exit(2);
}
/** The lists scanned: the reference image's, and the operator's app's. */
const lists = ["image.cdx.json", "app.cdx.json"];
const sbom = resolve(given);
const out = resolve(into);
mkdirSync(out, { recursive: true });
/** A failure's reason as one short line: the last its tool wrote. */
const reasonOf = (told: string) =>
	(
		told
			.trim()
			.split("\n")
			.filter((l) => l.trim() !== "")
			.at(-1) ?? "no reason given"
	).slice(0, 300);

let trivy = "(not read)";
let read: Read[];
/** The database, kept between the two runs in a volume of this run's own, removed however it ends. */
const cache = `release-scan-${process.pid}`;
try {
	const config = JSON.parse(
		readFileSync(join(import.meta.dirname, "..", "..", "scan.json"), "utf8"),
	) as { readonly trivy: string; readonly databases: readonly string[] };
	trivy = config.trivy;
	const scanned: Scanned[] = [];
	for (const list of lists) {
		if (!existsSync(join(sbom, list))) {
			scanned.push({ list, notScanned: "the release made no such list" });
			continue;
		}
		// The lists read alone; no token or setting of the run passed in.
		const ran = await endOf(
			docker(
				[
					"run",
					"--rm",
					"-v",
					`${sbom}:/in:ro`,
					"-v",
					`${cache}:/cache`,
					config.trivy,
					"sbom",
					"--scanners",
					"vuln",
					"--list-all-pkgs",
					"--format",
					"json",
					"--exit-code",
					"0",
					"--timeout",
					"10m",
					"--cache-dir",
					"/cache",
					"--db-repository",
					config.databases.join(","),
					`/in/${list}`,
				],
				dockerWithin.build,
			),
		);
		if (ran.status !== 0) {
			scanned.push({ list, notScanned: reasonOf(ran.stderr) });
			continue;
		}
		writeFileSync(join(out, list.replace(/\.cdx\.json$/, ".trivy.json")), `${ran.stdout}\n`);
		scanned.push({ list, output: ran.stdout });
	}
	read = scanned.map(readScan);
} catch (error) {
	// Whatever else went wrong is told in the report too, never as a failure.
	read = lists.map((list) => ({ list, notScanned: reasonOf(String(error)) }));
} finally {
	await endOf(docker(["volume", "rm", "-f", cache], dockerWithin.control));
}

const version = (() => {
	try {
		const listed = JSON.parse(readFileSync(join(sbom, "tarballs.json"), "utf8")) as {
			version?: string;
		}[];
		return listed[0]?.version ?? "";
	} catch {
		return "";
	}
})();
writeFileSync(join(out, "README.md"), reportOf(read, trivy, version));
for (const r of read)
	console.log(
		"notScanned" in r
			? `release-scan: ${r.list}: not scanned: ${r.notScanned}`
			: `release-scan: ${r.list}: ${r.findings.length} finding(s)`,
	);
process.exit(0);
