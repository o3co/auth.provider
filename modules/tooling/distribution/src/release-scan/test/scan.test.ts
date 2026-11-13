import { execFileSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterAll, expect, it } from "vitest";

// A `docker` of its own first on the path, logging each command and answering as the test's script says.
const scratch = mkdtempSync(join(tmpdir(), "release-scan-test-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
const scan = join(import.meta.dirname, "..", "scan.ts");
const config = JSON.parse(
	readFileSync(join(import.meta.dirname, "..", "..", "..", "scan.json"), "utf8"),
) as { trivy: string; databases: string[] };

const run = (name: string, answer: string, lists = ["image.cdx.json", "app.cdx.json"]) => {
	const dir = join(scratch, name);
	const bin = join(dir, "bin");
	const sbom = join(dir, "sbom");
	const out = join(dir, "out");
	mkdirSync(bin, { recursive: true });
	mkdirSync(sbom);
	for (const list of lists) writeFileSync(join(sbom, list), "{}");
	writeFileSync(join(sbom, "tarballs.json"), '[{"name":"x","version":"9.9.9"}]');
	const log = join(dir, "log");
	writeFileSync(
		join(bin, "docker"),
		`#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\nif [ "$1" = run ]; then\n${answer}\nfi\n`,
	);
	chmodSync(join(bin, "docker"), 0o755);
	const printed = execFileSync(process.execPath, [scan, sbom, out], {
		encoding: "utf8",
		env: { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH ?? ""}` },
	});
	return {
		printed,
		sbom,
		out,
		commands: readFileSync(log, "utf8").trim().split("\n"),
		report: readFileSync(join(out, "README.md"), "utf8"),
	};
};

it("runs the pinned Trivy on each list read-only, with no setting of the run passed in, and removes its volume", () => {
	const { commands, sbom, out, report } = run(
		"found",
		`echo '{"SchemaVersion":2,"Results":[{"Packages":[{"Name":"a"}],"Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"a","InstalledVersion":"1","FixedVersion":"2","Severity":"CRITICAL"}]}]}'`,
	);
	const runs = commands.filter((c) => c.startsWith("run "));
	expect(runs).toHaveLength(2);
	for (const [i, list] of ["image.cdx.json", "app.cdx.json"].entries()) {
		const c = runs[i] ?? "";
		expect(c).toContain(`-v ${sbom}:/in:ro`);
		expect(c).toContain(` ${config.trivy} sbom `);
		expect(c).toContain("--exit-code 0");
		expect(c).toContain("--list-all-pkgs");
		expect(c).toContain(`--db-repository ${config.databases.join(",")}`);
		expect(c.endsWith(`/in/${list}`)).toBe(true);
		expect(c).not.toMatch(/(^| )(-e|--env|--env-file)( |=)/);
	}
	const volume = /-v (release-scan-\d+):\/cache/.exec(runs[0] ?? "")?.[1];
	expect(volume).toBeDefined();
	expect(commands.at(-1)).toBe(`volume rm -f ${volume}`);
	expect(existsSync(join(out, "image.trivy.json"))).toBe(true);
	expect(existsSync(join(out, "app.trivy.json"))).toBe(true);
	expect(report).toContain("auth-provider 9.9.9");
	expect(report).toContain("| `app.cdx.json` | 1 | 1 | 0 | 0 | 0 | 0 |");
});

it("exits 0 when Trivy fails, telling each list not scanned with Trivy's last line", () => {
	const { printed, out, report, commands } = run(
		"failed",
		`echo 'INFO downloading' >&2; echo 'FATAL db: 429 too many requests' >&2; exit 1`,
	);
	expect(report).toContain("| `image.cdx.json` | not scanned: FATAL db: 429 too many requests |");
	expect(report).toContain("| `app.cdx.json` | not scanned: FATAL db: 429 too many requests |");
	expect(printed).toContain("not scanned");
	expect(existsSync(join(out, "app.trivy.json"))).toBe(false);
	expect(commands.at(-1)).toMatch(/^volume rm -f release-scan-\d+$/);
});

it("tells a list the release did not make as not scanned", () => {
	const { report, commands } = run(
		"missing",
		`echo '{"SchemaVersion":2,"Results":[{"Packages":[{"Name":"a"}]}]}'`,
		["app.cdx.json"],
	);
	expect(report).toContain("| `image.cdx.json` | not scanned: the release made no such list |");
	expect(report).toContain("| `app.cdx.json` | 1 | 0 | 0 | 0 | 0 | 0 |");
	expect(commands.filter((c) => c.startsWith("run "))).toHaveLength(1);
});

it("tells a list in which Trivy read no package as not scanned, never as clean", () => {
	const { report } = run("none-read", `echo '{"SchemaVersion":2,"Results":[]}'`);
	expect(report).toContain("| `image.cdx.json` | not scanned: Trivy read no packages |");
	expect(report).toContain("| `app.cdx.json` | not scanned: Trivy read no packages |");
});
