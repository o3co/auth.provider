#!/usr/bin/env node
/**
 * The image of the app the packed `create-auth-provider` makes from the tarballs in the directory
 * named, built as its guide says, scanned by Trivy, its image pinned in `scan.json`, and its Node
 * held to Node's security releases; the verdict written into the directory named. Exits 0 only
 * where the scan passed.
 */
import { randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { docker } from "@mod/docker-client";
import { entrance, fullApp } from "../full-app/full-app.ts";
import { packedOf } from "../release/seal.ts";
import { buildWithin, commandWithin, dockerMissing, images } from "../release-check/image.ts";
import { endOf } from "../release-sbom/removal.ts";
import { trivyArguments, type Verdict, verdictOf } from "./gate.ts";
import { fetchNodeIndex, nodeChecked } from "./node.ts";

const [given, into] = process.argv.slice(2);
if (!given || !into) {
	console.error(
		"image-scan: name the directory the tarballs are in, and the directory to write the verdict in",
	);
	process.exit(2);
}
const config = JSON.parse(
	readFileSync(join(import.meta.dirname, "..", "..", "scan.json"), "utf8"),
) as { readonly trivy: string; readonly databases: readonly string[] };
const tarballs = resolve(given);
const out = resolve(into);
mkdirSync(out, { recursive: true });
const byName: Record<string, string> = Object.fromEntries(
	readdirSync(tarballs)
		.filter((f) => f.endsWith(".tgz"))
		.map((f) => join(tarballs, f))
		.map((f) => [packedOf(f).name, f]),
);
const tool = byName[entrance];
const about = {
	trivy: config.trivy,
	app: `The \`full\` app with every feature that opts in, made by \`${entrance}\`${tool ? ` ${packedOf(tool).version}` : ""}`,
};
/** A scan that could not be made: failed, told with why. */
const notScanned = (why: string) =>
	verdictOf({ status: 1, stdout: "", stderr: why }, { notChecked: "no image was built" }, about);

const missing = await dockerMissing();
let verdict: Verdict;
if (missing) verdict = notScanned(`Docker is not reachable: ${missing}`);
else if (!tool) verdict = notScanned(`no ${entrance} tarball in ${tarballs}`);
else {
	const scratch = mkdtempSync(join(tmpdir(), "image-scan-"));
	const run = images(`image-scan-${randomUUID()}`, { dir: tarballs, byName }, scratch);
	try {
		const { app } = fullApp(byName, scratch);
		const image = await run.build(app, "full", true);
		await docker(["save", image, "-o", join(scratch, "image.tar")], buildWithin);
		const ran = await endOf(
			docker(trivyArguments({ ...config, dir: scratch, file: "image.tar" }), buildWithin),
		);
		if (ran.stdout.trim() !== "") writeFileSync(join(out, "image.trivy.json"), `${ran.stdout}\n`);
		const version = await docker(
			["run", "--rm", "--network", "none", "--entrypoint", "node", image, "-p", "process.version"],
			commandWithin,
		);
		verdict = verdictOf(ran, await nodeChecked(version, fetchNodeIndex), about);
	} catch (error) {
		// Whatever else went wrong fails the scan, told in the verdict.
		verdict = notScanned(error instanceof Error ? error.message : String(error));
	} finally {
		try {
			await run.remove();
		} catch (error) {
			console.error(`image-scan: the images it built may be left: ${String(error)}`);
		}
		rmSync(scratch, { recursive: true, force: true });
	}
}
writeFileSync(join(out, "README.md"), verdict.report);
console.log(verdict.report);
process.exit(verdict.passed ? 0 : 1);
