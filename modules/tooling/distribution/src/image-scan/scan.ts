#!/usr/bin/env node
/**
 * The image of the app the packed `create-auth-provider` makes from the tarballs in the directory
 * named, built as its guide says and scanned by Trivy, its image pinned in `scan.json`; the verdict
 * written into the directory named. Exits 0 only where the scan passed.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { optIns } from "@mod/combinations";
import { docker } from "@mod/docker-client";
import { packedOf } from "../release/seal.ts";
import { buildWithin, dockerMissing, images, overridesFile } from "../release-check/image.ts";
import { endOf } from "../release-sbom/removal.ts";
import { trivyArguments, verdictOf } from "./gate.ts";

const [given, into] = process.argv.slice(2);
if (!given || !into) {
	console.error(
		"image-scan: name the directory the tarballs are in, and the directory to write the verdict in",
	);
	process.exit(2);
}
const missing = await dockerMissing();
if (missing) {
	console.error(
		`image-scan: builds and scans the app's image, and Docker is not reachable: ${missing}`,
	);
	process.exit(1);
}
const config = JSON.parse(
	readFileSync(join(import.meta.dirname, "..", "..", "scan.json"), "utf8"),
) as { readonly trivy: string; readonly databases: readonly string[] };
const tarballs = resolve(given);
const out = resolve(into);
mkdirSync(out, { recursive: true });
const byName = Object.fromEntries(
	readdirSync(tarballs)
		.filter((f) => f.endsWith(".tgz"))
		.map((f) => join(tarballs, f))
		.map((f) => [packedOf(f).name, f]),
);
const entrance = "@o3co/create-auth-provider";
const version = byName[entrance] ? packedOf(byName[entrance]).version : "";
const scratch = mkdtempSync(join(tmpdir(), "image-scan-"));
const run = images(`image-scan-${randomUUID()}`, { dir: tarballs, byName }, scratch);

let verdict: ReturnType<typeof verdictOf>;
try {
	// The entrance installed from the tarballs alone, as the release check installs it; nothing it holds runs.
	const tool = join(scratch, "entrance");
	mkdirSync(tool);
	writeFileSync(
		join(tool, "package.json"),
		JSON.stringify({
			name: "entrance",
			private: true,
			dependencies: { [entrance]: `file:${byName[entrance]}` },
		}),
	);
	writeFileSync(join(tool, "pnpm-workspace.yaml"), overridesFile(byName));
	execFileSync(
		"pnpm",
		["install", "--prefer-offline", "--no-frozen-lockfile", "--ignore-scripts"],
		{
			cwd: tool,
			stdio: ["ignore", "ignore", "inherit"],
		},
	);
	// The full template with every feature that opts in: every package an app of the release can install.
	const app = join(scratch, "app");
	execFileSync(
		join(tool, "node_modules", ".bin", "create-auth-provider"),
		[app, "--pattern", "full", ...optIns().flatMap((name) => ["--add", name])],
		{ stdio: "pipe" },
	);
	const image = await run.build(app, "full", true);
	await docker(["save", image, "-o", join(scratch, "image.tar")], buildWithin);
	const ran = await endOf(
		docker(trivyArguments({ ...config, dir: scratch, file: "image.tar" }), buildWithin),
	);
	if (ran.stdout.trim() !== "") writeFileSync(join(out, "image.trivy.json"), `${ran.stdout}\n`);
	verdict = verdictOf(ran, {
		trivy: config.trivy,
		app: `The \`full\` app with every feature that opts in, made by \`${entrance}\` ${version}`,
	});
} catch (error) {
	// Whatever else went wrong fails the scan, told in the verdict.
	verdict = verdictOf(
		{ status: 1, stdout: "", stderr: error instanceof Error ? error.message : String(error) },
		{ trivy: config.trivy, app: `The \`full\` app made by \`${entrance}\` ${version}` },
	);
} finally {
	try {
		await run.remove();
	} catch (error) {
		console.error(`image-scan: the images it built may be left: ${String(error)}`);
	}
	rmSync(scratch, { recursive: true, force: true });
}
writeFileSync(join(out, "README.md"), verdict.report);
console.log(verdict.report);
process.exit(verdict.passed ? 0 : 1);
