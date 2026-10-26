import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { patterns } from "@mod/create-app";
import { buildBundles } from "../build.ts";
import { readBundles } from "../contract.ts";
import { outsideScene } from "../outside-scene/contract.ts";
import { packedOf, packRelease, zodOf } from "../release/contract.ts";
import { releaseOf } from "../workspace.ts";
import { sweptRun } from "./containers/container.ts";
import { tarballsToCheck } from "./given/given.ts";
import { helperScene } from "./helpers.ts";
import { dockerMissing, images, overridesFile } from "./image.ts";

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
const missing = await dockerMissing();
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
// The tarballs named, as the release publishes them; else packed as the release packs them, the index sealed in between.
const packed = tarballsToCheck(process.argv[2], (into) => packRelease(root, into), scratch);
if ("problems" in packed) {
	for (const problem of packed.problems) console.error(problem);
	process.exit(1);
}
const tarballs = packed.dir;
const overrides: Record<string, string> = {};
for (const tarball of packed.tarballs) {
	const { name } = packedOf(tarball);
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

/**
 * An app assembled by hand from the tarballs, as one keeping its own composition root does:
 * combinations' full names made published, each module imported, and assembled to the kernel's
 * refusals, as no configuration is given.
 */
const hand = join(scratch, "hand");
mkdirSync(hand);
const scaffold = "@o3co/auth-provider-scaffold";
const handOn = (dependencies: Record<string, string>) =>
	writeFileSync(
		join(hand, "package.json"),
		JSON.stringify({ name: "release-check-hand", private: true, type: "module", dependencies }),
	);
try {
	handOn({ [scaffold]: `file:${overrides[scaffold]}` });
	install(hand);
	const names = `import { full, published } from "${scaffold}/combinations";
process.stdout.write(JSON.stringify(published([...full(), "@mod/kernel"])));`;
	const entries = JSON.parse(
		execFileSync("node", ["--input-type=module", "-e", names], { cwd: hand, encoding: "utf8" }),
	) as { name: string; package: string; entry: string }[];
	handOn(Object.fromEntries(entries.map((e) => [e.package, `file:${overrides[e.package]}`])));
	install(hand);
	const kernel = entries.find((e) => e.name === "@mod/kernel")?.entry;
	const modules = entries.filter((e) => e.name !== "@mod/kernel").map((e) => `${e.entry}/module`);
	writeFileSync(
		join(hand, "main.js"),
		`import { assemble, BootRefused } from ${JSON.stringify(kernel)};
const modules = await Promise.all(${JSON.stringify(modules)}.map(async (m) => (await import(m)).default));
try {
	await assemble({ modules, config: {} });
} catch (error) {
	if (!BootRefused.is(error)) throw error;
	process.stdout.write(\`\${modules.length} modules imported, refused at boot\`);
	process.exit(0);
}
throw new Error("booted with no configuration");
`,
	);
	say(`by hand: ${execFileSync("node", ["main.js"], { cwd: hand, encoding: "utf8" })}`);
} catch (error) {
	const told = error as { stdout?: Buffer; stderr?: Buffer; message: string };
	problems.push(`by hand: ${told.stdout ?? ""}${told.stderr ?? ""}${told.message}`);
	say("by hand: failed");
}

// Each launch its own: no name, nor label, of an earlier check's is ever this one's.
const runName = `release-check-${randomUUID()}`;
const run = images(runName, { dir: tarballs, byName: overrides }, scratch);

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
		const image = await run.build(app, name);
		const tools = await run.carriedBy(image);
		if (tools.length > 0)
			problems.push(`${name}: its image holds a package manager: ${tools.join(", ")}`);
		say(`${name}: ${await run.booted(app, image)}`);
		// The resolver's helpers as a deployment constrains them, on one pattern's image.
		if (name === "simple-web") {
			try {
				say(`helpers: ${await helperScene(run, app, image)}`);
			} catch (error) {
				problems.push(`helpers: ${error instanceof Error ? error.message : String(error)}`);
				say("helpers: failed");
			}
		}
	} catch (error) {
		const told = error as { stdout?: Buffer; stderr?: Buffer; message: string };
		problems.push(`${name}: ${told.stdout ?? ""}${told.stderr ?? ""}${told.message}`);
		say(`${name}: failed`);
	}
}

// The cleanup the check stands by: every container of this run, one whose making showed late too.
try {
	await sweptRun(runName);
} catch (error) {
	problems.push(`containers: ${error instanceof Error ? error.message : String(error)}`);
}
await run.remove();

const zod = zodOf(readFileSync(join(root, "pnpm-lock.yaml"), "utf8"));
try {
	if (typeof zod === "string") throw new Error(zod);
	const scene = { tarballs, scratch, version: packedOf(overrides[entrance] as string).version };
	say(`outside: ${await outsideScene({ ...scene, zod: zod.version, pattern: "simple-web" })}`);
} catch (error) {
	problems.push(`outside: ${error instanceof Error ? error.message : String(error)}`);
	say("outside: failed");
}

for (const problem of problems) console.error(problem);
say(problems.length === 0 ? `release: ok (${scratch})` : `release: ${problems.length}`);
process.exit(problems.length === 0 ? 0 : 1);
