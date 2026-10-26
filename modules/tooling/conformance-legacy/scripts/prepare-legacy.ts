import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { legacyCommitOf, legacyDir } from "../src/dir.ts";
import { extras } from "./extras.mjs";

const source = process.env.LEGACY_SOURCE;
// The commit this tree names, never a ref someone could move.
const commit = legacyCommitOf();
if (!source) {
	process.stderr.write(
		`set LEGACY_SOURCE (a local clone holding commit ${commit}, read only); LEGACY_COMMIT and LEGACY_DIR (a work dir) are optional\n`,
	);
	process.exit(64);
}
const dir = legacyDir();
const run = (cmd: string, args: string[], cwd?: string) =>
	execFileSync(cmd, args, { stdio: "inherit", ...(cwd ? { cwd } : {}) });
if (!existsSync(dir)) {
	run("git", ["clone", "--local", "--no-hardlinks", "--no-checkout", source, dir]);
	run("git", ["-c", "advice.detachedHead=false", "checkout", "--detach", commit], dir);
}
// Before anything of the clone runs: it is that commit, a build kept from another one included.
const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();
if (head !== commit) {
	process.stderr.write(
		`the legacy dir ${dir} holds commit ${head}, not ${commit}: remove it, or set LEGACY_DIR to another\n`,
	);
	process.exit(1);
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
