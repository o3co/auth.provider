import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { patterns } from "@mod/create-app";
import { buildBundles } from "./build.ts";
import { readBundles } from "./contract.ts";
import { dockerMissing, images, overridesFile } from "./image.ts";
import { releaseOf } from "./workspace.ts";

/**
 * Checks the release as an operator meets it: every bundle packed, an app of each pattern made by
 * the packed create-auth-provider, installed from the tarballs alone, its entry type-checked, and
 * booted on trial settings in the image its Dockerfile builds, to readiness, or to its refusals
 * where it needs a Redis it cannot reach.
 */
const root = process.env.INIT_CWD ?? process.cwd();
const workspace = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const out = join(root, "dist", "bundles");
const say = (text: string) => process.stdout.write(`${text}\n`);
const problems: string[] = [];

// No boot is skipped: without Docker the release is not checked as it is deployed.
const missing = dockerMissing();
if (missing) {
	console.error(
		`release:check boots each app in its image, and Docker is not reachable: ${missing}`,
	);
	process.exit(1);
}

const { problems: unbuilt } = buildBundles({
	bundles: readBundles(root),
	release: releaseOf(root) ?? { version: workspace.version },
	out,
	licenseFile: join(root, "LICENSE"),
});
if (unbuilt.length > 0) {
	for (const problem of unbuilt) console.error(problem);
	process.exit(1);
}

const scratch = mkdtempSync(join(tmpdir(), "release-check-"));
const tarballs = join(scratch, "tarballs");
mkdirSync(tarballs);
const overrides: Record<string, string> = {};
for (const dir of readdirSync(out)) {
	const { name } = JSON.parse(readFileSync(join(out, dir, "package.json"), "utf8"));
	const packed = execFileSync("pnpm", ["pack", "--pack-destination", tarballs], {
		cwd: join(out, dir),
		encoding: "utf8",
	})
		.trim()
		.split("\n")
		.findLast((line) => line.endsWith(".tgz"));
	if (!packed) throw new Error(`${name}: pnpm pack named no tarball`);
	const tarball = packed.startsWith("/") ? packed : join(tarballs, packed);
	// npm and pnpm alike ship what the tarball holds: the license must be in it.
	const held = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" }).split("\n");
	if (!held.includes("package/LICENSE")) problems.push(`${name}: its tarball holds no LICENSE`);
	overrides[name] = tarball;
}
say(`packed ${Object.keys(overrides).length}`);

/** A project installing from the tarballs alone; any outside package comes from the store first. */
const install = (dir: string) => {
	writeFileSync(join(dir, "pnpm-workspace.yaml"), overridesFile(overrides));
	execFileSync("pnpm", ["install", "--prefer-offline", "--no-frozen-lockfile"], {
		cwd: dir,
		stdio: "pipe",
	});
};

const tool = join(scratch, "tool");
mkdirSync(tool);
const entrance = "@o3co/create-auth-provider";
writeFileSync(
	join(tool, "package.json"),
	JSON.stringify({
		name: "release-check-tool",
		private: true,
		dependencies: { [entrance]: `file:${overrides[entrance]}` },
	}),
);
install(tool);

const run = images(`release-check-${process.pid}`, { dir: tarballs, byName: overrides }, scratch);

const tsc = join(root, "node_modules", ".bin", "tsc");
for (const name of patterns().map((pattern) => pattern.name)) {
	const app = join(scratch, `app-${name}`);
	try {
		execFileSync(
			join(tool, "node_modules", ".bin", "create-auth-provider"),
			[app, "--pattern", name],
			{
				stdio: "pipe",
			},
		);
		install(app);
		execFileSync(
			tsc,
			[
				"--noEmit",
				"--strict",
				"--target",
				"es2024",
				"--module",
				"nodenext",
				"--moduleResolution",
				"nodenext",
				"--allowImportingTsExtensions",
				"--skipLibCheck",
				"--types",
				"node",
				"--typeRoots",
				join(root, "node_modules", "@types"),
				"src/main.ts",
			],
			{ cwd: app, stdio: "pipe" },
		);
		say(`${name}: ${await run.booted(app, run.build(app, name))}`);
	} catch (error) {
		const told = error as { stdout?: Buffer; stderr?: Buffer; message: string };
		problems.push(`${name}: ${told.stdout ?? ""}${told.stderr ?? ""}${told.message}`);
		say(`${name}: failed`);
	}
}

run.remove();

for (const problem of problems) console.error(problem);
say(problems.length === 0 ? `release: ok (${scratch})` : `release: ${problems.length}`);
process.exit(problems.length === 0 ? 0 : 1);
