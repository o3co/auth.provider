#!/usr/bin/env node
/**
 * Before anything is published: the release's lists of what it ships, made from the tarballs it will
 * publish, into the directory named. Each list is CycloneDX, written by an established tool pinned
 * where this package names it (`sbom.json`), the release's own components named as npm publishes
 * them; the components bundles hold inside are listed from their declarations. Any list that does not
 * hold every tarball, or a bundled file undeclared, stops it.
 */
import { execFileSync } from "node:child_process";
import {
	copyFileSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { optIns } from "@mod/combinations";
import { readBundles } from "../contract.ts";
import { packedOf } from "../release/seal.ts";
import { docker } from "../release-check/containers/docker.ts";
import { buildWithin, commandWithin, images, overridesFile } from "../release-check/image.ts";
import { type Bom, coverageProblems, type Declared, insideBom, npmNamed } from "./boms.ts";
import { endOf, notRemoved } from "./removal.ts";

const [given, into] = process.argv.slice(2);
if (!given || !into) {
	console.error(
		"release-sbom: name the directory the tarballs are in, and the directory to write the lists in",
	);
	process.exit(2);
}
const root = join(import.meta.dirname, "..", "..", "..", "..", "..");
const config = JSON.parse(
	readFileSync(join(import.meta.dirname, "..", "..", "sbom.json"), "utf8"),
) as {
	readonly cyclonedx: string;
	readonly syft: string;
};
const tarballs = resolve(given);
const out = resolve(into);
mkdirSync(out, { recursive: true });
const files = readdirSync(tarballs)
	.filter((f) => f.endsWith(".tgz"))
	.map((f) => join(tarballs, f));
const packed = files.map(packedOf);
const byName = Object.fromEntries(files.map((f) => [packedOf(f).name, f]));
const problems: string[] = [];
const scratch = mkdtempSync(join(tmpdir(), "release-sbom-"));

const sbom = (dir: string, scope: "--prod" | "--dev") =>
	JSON.parse(
		execFileSync(
			"pnpm",
			["sbom", "--sbom-format", "cyclonedx", "--sbom-spec-version", config.cyclonedx, scope],
			{ cwd: dir, encoding: "utf8", maxBuffer: 1 << 28 },
		),
	) as Bom;
/** A project installed from the tarballs alone, as the release check installs one; nothing it holds runs. */
const install = (dir: string) => {
	writeFileSync(join(dir, "pnpm-workspace.yaml"), overridesFile(byName));
	execFileSync(
		"pnpm",
		["install", "--prefer-offline", "--no-frozen-lockfile", "--ignore-scripts"],
		{
			cwd: dir,
			stdio: ["ignore", "ignore", "inherit"],
		},
	);
};
const named = (bom: Bom, what: string) => {
	const result = npmNamed(bom, packed);
	if ("problems" in result) {
		problems.push(...result.problems.map((p) => `${what}: ${p}`));
		return bom;
	}
	return result.bom;
};
const write = (file: string, value: unknown) =>
	writeFileSync(
		join(out, file),
		typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`,
	);

try {
	// The entrance, installed alone, as an operator runs it with npx.
	const entrance = "@o3co/create-auth-provider";
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
	install(tool);
	const entranceBom = named(sbom(tool, "--prod"), "entrance");
	write("entrance.cdx.json", entranceBom);
	copyFileSync(join(tool, "pnpm-lock.yaml"), join(out, "entrance.pnpm-lock.yaml"));

	// The operator's app: the full template with every feature that opts in, made by the entrance.
	const app = join(scratch, "app");
	execFileSync(
		join(tool, "node_modules", ".bin", "create-auth-provider"),
		[app, "--pattern", "full", ...optIns().flatMap((name) => ["--add", name])],
		{ stdio: "pipe" },
	);
	install(app);
	const appBom = named(sbom(app, "--prod"), "app");
	write("app.cdx.json", appBom);
	copyFileSync(join(app, "pnpm-lock.yaml"), join(out, "app.pnpm-lock.yaml"));
	problems.push(...coverageProblems([appBom, entranceBom], packed));

	// What the bundles hold inside, from each manifest's declaration and the bundled files shipped.
	const declared: Declared[] = readBundles(root).flatMap((b) =>
		b.members.flatMap((m) =>
			Object.entries(
				(JSON.parse(readFileSync(join(m.dir, "package.json"), "utf8")).bundledInside ??
					{}) as Record<string, string[]>,
			).map(([file, packages]) => ({ member: basename(m.dir), file, packages })),
		),
	);
	const shipped = files.map((f) => {
		const listed = execFileSync("tar", ["-tzf", f], { encoding: "utf8" }).split("\n");
		const bundled = listed.filter((path) => path.endsWith(".bundled.mjs"));
		const { name, version } = packedOf(f);
		return {
			name,
			version,
			files: new Map(
				bundled.map((path) => [
					path,
					execFileSync("tar", ["-xzOf", f, path], { encoding: "utf8", maxBuffer: 1 << 28 }),
				]),
			),
		};
	});
	const inside = insideBom(shipped, declared);
	if ("problems" in inside) problems.push(...inside.problems);
	else write("inside.cdx.json", inside.bom);

	// The tools that build and check the release: the workspace's development dependencies.
	const tools = sbom(root, "--dev");
	write("build-tools.cdx.json", tools);
	const listedTools = new Set(
		tools.components.map((c) => (c.group ? `${c.group}/${c.name}` : c.name)),
	);
	for (const b of readBundles(root)) {
		for (const m of b.members) {
			const dev = Object.keys(
				JSON.parse(readFileSync(join(m.dir, "package.json"), "utf8")).devDependencies ?? {},
			);
			for (const name of dev.filter((d) => !d.startsWith("@mod/") && !listedTools.has(d))) {
				problems.push(`build tools: ${m.name}'s ${name} is in no list`);
			}
		}
	}

	// The operator's app's image, built from its Dockerfile on the tarballs, as the release check builds it.
	const run = `release-sbom-${process.pid}`;
	const image = `${run}:full`;
	try {
		await images(run, { dir: tarballs, byName }, scratch).build(app, "full");
		const id = await docker(["image", "inspect", "--format", "{{.Id}}", image], commandWithin);
		// Writing out and reading the whole image take no longer than building it.
		await docker(["save", image, "-o", join(scratch, "image.tar")], buildWithin);
		const scanned = await endOf(
			docker(
				[
					"run",
					"--rm",
					"-v",
					`${scratch}:/in:ro`,
					config.syft,
					"docker-archive:/in/image.tar",
					"-o",
					`cyclonedx-json@${config.cyclonedx}`,
					"-q",
				],
				buildWithin,
			),
		);
		if (scanned.status !== 0)
			problems.push(`image: ${config.syft} could not list it: ${scanned.stderr.trim()}`);
		else write("image.cdx.json", scanned.stdout);
		write("image.json", {
			id,
			syft: config.syft,
			note: "the reference image this release built from its Dockerfile; an operator's own build takes the Node of its day",
		});
	} finally {
		// Removed however the build or the listing ended, the base stage's image too, and held to be gone.
		const removing = [image, `${run}:base`];
		const answer = await endOf(docker(["image", "rm", "-f", ...removing], commandWithin));
		const listed = await endOf(
			docker(["image", "ls", "--format", "{{.Repository}}:{{.Tag}}"], commandWithin),
		);
		const left = notRemoved(removing, answer, listed);
		if (left) problems.push(left);
	}

	write(
		"tarballs.json",
		packed.map(({ name, version, integrity }) => ({
			name,
			version,
			integrity,
			file: basename(byName[name] ?? ""),
		})),
	);
	write("README.md", readme(packed[0]?.version ?? ""));
} finally {
	rmSync(scratch, { recursive: true, force: true });
}

for (const problem of problems) console.error(`release-sbom: ${problem}`);
console.log(
	problems.length === 0
		? `release-sbom: the lists of ${packed.length} tarballs written to ${out}`
		: `release-sbom: ${problems.length} problem(s); nothing may be published`,
);
process.exit(problems.length === 0 ? 0 : 1);

/** What each file of the lists is, for the one who reads them. */
function readme(version: string) {
	return `# What auth-provider ${version} ships

Lists in CycloneDX ${config.cyclonedx} JSON, made by the release from the tarballs it published.

- \`app.cdx.json\`: the operator's app, the full template with every feature that opts in, as \`create-auth-provider\` makes it, installed (\`dependencies\` alone); its resolved lock is \`app.pnpm-lock.yaml\`.
- \`entrance.cdx.json\`: \`create-auth-provider\`, the entrance an operator runs with npx to make the app, installed alone; its lock is \`entrance.pnpm-lock.yaml\`.
- \`inside.cdx.json\`: the packages a published bundle holds inside one of its files, which no dependency tree shows, at the versions the files hold.
- \`build-tools.cdx.json\`: the tools that build and check the release, the workspace's development dependencies; no operator installs them.
- \`image.cdx.json\`: the image this release built from the app's Dockerfile, listed by syft (\`image.json\` names it, its id and syft's version). It is a reference: the Dockerfile takes one Node 24 minor at its latest patch, so an operator's build of another day may hold another Node patch. pnpm runs only in the image's build (its deps stage); the image starts the app with node, and holds no package manager but npm, the corepack and the yarn Node's image bundles taken out.
- \`tarballs.json\`: each tarball published, its name, version and npm integrity, which the release's own components in the lists carry as their SHA-512.

The release's own components are named as npm publishes them (\`pkg:npm/%40o3co/<name>@<version>\`), with the hash of the very tarball published.

The app and the entrance are installed for these lists with no install script run (\`--ignore-scripts\`): what is installed, and so the tree listed, is the same as an operator's install, which runs them.
`;
}
