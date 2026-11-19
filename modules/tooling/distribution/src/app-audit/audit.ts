#!/usr/bin/env node
/**
 * The known vulnerabilities, at every level, in what the app the packed `create-auth-provider`
 * makes installs: the app made from the tarballs in the directory named, installed from them with
 * the lockfile that install writes, and `pnpm audit` run in it. Exits 0 only where the audit ran
 * and found nothing.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fullApp, installFromTarballs } from "../full-app/full-app.ts";
import { packedOf } from "../release/seal.ts";

const given = process.argv[2];
if (!given) {
	console.error("app-audit: name the directory the tarballs are in");
	process.exit(2);
}
const tarballs = resolve(given);
const byName: Record<string, string> = Object.fromEntries(
	readdirSync(tarballs)
		.filter((f) => f.endsWith(".tgz"))
		.map((f) => join(tarballs, f))
		.map((f) => [packedOf(f).name, f]),
);
const scratch = mkdtempSync(join(tmpdir(), "app-audit-"));
let status: number;
try {
	const { app } = fullApp(byName, scratch);
	installFromTarballs(app, byName);
	const audit = spawnSync("pnpm", ["audit", "--audit-level=low"], { cwd: app, stdio: "inherit" });
	// An audit that could not run is no clean one.
	status = audit.status ?? 1;
	if (audit.error) console.error(`app-audit: pnpm audit did not run: ${audit.error.message}`);
} catch (error) {
	console.error(
		`app-audit: the app could not be made: ${error instanceof Error ? error.message : String(error)}`,
	);
	status = 1;
} finally {
	rmSync(scratch, { recursive: true, force: true });
}
process.exit(status === 0 ? 0 : 1);
