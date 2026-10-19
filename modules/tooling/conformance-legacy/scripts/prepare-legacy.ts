import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { legacyDir, legacyVersion } from "../src/dir.ts";
import { extras } from "./extras.mjs";

const source = process.env.LEGACY_SOURCE;
// The legacy version's tag, the one the build's dir is named for, unless another is asked.
const branch = process.env.LEGACY_BRANCH || `v${legacyVersion}`;
if (!source) {
	process.stderr.write(
		`set LEGACY_SOURCE (a local clone, read only); LEGACY_BRANCH (default ${branch}) and LEGACY_DIR (a work dir) are optional\n`,
	);
	process.exit(64);
}
const dir = legacyDir();
const run = (cmd: string, args: string[], cwd?: string) =>
	execFileSync(cmd, args, { stdio: "inherit", ...(cwd ? { cwd } : {}) });
if (!existsSync(dir)) {
	run("git", ["clone", "--local", "--no-hardlinks", "--branch", branch, source, dir]);
}
// The standalone build, and the packages the composed entry adds, with what each depends on.
const added = Object.values(extras)
	.flat()
	.map(
		(name) => JSON.parse(readFileSync(join(dir, "packages", name, "package.json"), "utf8")).name,
	);
const filters = ["@o3co/auth-provider-standalone", ...added].flatMap((name) => [
	"--filter",
	`${name}...`,
]);
run("pnpm", ["install", "--frozen-lockfile", ...filters], dir);
run("pnpm", [...filters, "run", "build"], dir);
process.stdout.write(`legacy ready in ${join(dir, "templates", "standalone")}\n`);
