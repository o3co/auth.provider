import {
	copyFileSync,
	cpSync,
	existsSync,
	globSync,
	mkdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import ts from "typescript";
import type { Bundle } from "./contract.ts";
import {
	aboutFields,
	aboutOf,
	bundleManifest,
	type MemberManifest,
	publicNameOf,
	published,
	type Release,
	readmeOf,
} from "./publish.ts";

/** A file the build leaves out: tests, test tools (a trial file among them), and the TypeScript it compiles instead. */
const leftOut = (path: string) =>
	/(^|\/)(node_modules|test)(\/|$)/.test(path) ||
	path === "package.json" ||
	path === "trial.conf" ||
	path.endsWith(".ts");

/** How the members compile: as the workspace checks them, emitting JS and declarations. */
const compiling = (
	rootDir: string,
	outDir: string,
	paths: Record<string, string[]>,
): ts.CompilerOptions => ({
	target: ts.ScriptTarget.ES2024,
	lib: ["lib.es2024.d.ts"],
	module: ts.ModuleKind.NodeNext,
	moduleResolution: ts.ModuleResolutionKind.NodeNext,
	types: ["node"],
	strict: true,
	noUncheckedIndexedAccess: true,
	exactOptionalPropertyTypes: true,
	verbatimModuleSyntax: true,
	erasableSyntaxOnly: true,
	allowImportingTsExtensions: true,
	rewriteRelativeImportExtensions: true,
	declaration: true,
	skipLibCheck: true,
	rootDir,
	outDir,
	paths,
});

const where = (diagnostic: ts.Diagnostic) => {
	const text = ts.flattenDiagnosticMessageText(diagnostic.messageText, " ");
	if (!diagnostic.file || diagnostic.start === undefined) return text;
	const { line } = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
	return `${diagnostic.file.fileName}:${line + 1}: ${text}`;
};

type Manifests = ReadonlyMap<
	string,
	{ readonly bundle: string; readonly path: string; readonly written: MemberManifest }
>;

/**
 * The index a bundle may ask for: each shipped member's manifest as written, its public package
 * and entry, and its section's example, for a module that composes them from a bundle.
 */
function indexOf(manifests: Manifests, version: string): string {
	const packages = [...manifests.entries()]
		.sort(([a], [b]) => (a < b ? -1 : 1))
		.map(([name, { bundle, path, written }]) => {
			const {
				devDependencies: _,
				scripts: __,
				...manifest
			} = JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
			const fragment = join(path, "config.example");
			return {
				name,
				package: publicNameOf(bundle),
				entry: `${publicNameOf(bundle)}/${written.dir}`,
				manifest,
				...(existsSync(fragment) ? { fragment: readFileSync(fragment, "utf8") } : {}),
			};
		});
	return `${JSON.stringify({ version, packages }, null, "\t")}\n`;
}

/**
 * An entrance a bundle declares: a package of its own name whose command calls a member's `run`
 * with its arguments, and what it says of itself.
 */
interface Entrance {
	readonly bin: string;
	readonly runs: string;
	readonly description?: unknown;
	readonly keywords?: unknown;
}

function entranceOf(
	name: string,
	entrance: Entrance,
	placed: (name: string) => { readonly bundle: string; readonly dir: string } | undefined,
	release: Release,
): { readonly manifest: object; readonly main: string } | { readonly problem: string } {
	const { version } = release;
	const found = placed(entrance.runs);
	if (!found) return { problem: `${name}: runs ${entrance.runs}, of no shipped member` };
	const described = aboutOf(name, entrance, release);
	if ("problem" in described) return described;
	const runs = JSON.stringify(`${publicNameOf(found.bundle)}/${found.dir}`);
	return {
		manifest: {
			name,
			version,
			...aboutFields(described.about),
			type: "module",
			...(release.license ? { license: release.license } : {}),
			...(release.repository ? { repository: { type: "git", url: release.repository } } : {}),
			...(release.engines ? { engines: release.engines } : {}),
			bin: { [entrance.bin]: "./main.js" },
			dependencies: { [publicNameOf(found.bundle)]: version },
		},
		main: `#!/usr/bin/env node\nimport { run } from ${runs};\n\nprocess.exitCode = await run(process.argv.slice(2));\n`,
	};
}

/**
 * Builds each shipped bundle into `out/<concern directory>`: its members compiled, named publicly,
 * with their other files, and its manifest. Answers the bundles built, or what kept them from it.
 */
export function buildBundles(input: {
	readonly bundles: readonly Bundle[];
	readonly release: Release;
	readonly out: string;
	/** The workspace's license file, put in each bundle and entrance so any packer ships it. */
	readonly licenseFile?: string;
}): { readonly built: readonly string[]; readonly problems: readonly string[] } {
	const shipped = input.bundles.filter((bundle) => bundle.shipped);
	if (shipped.length === 0) return { built: [], problems: [] };
	const rootDir = dirname((shipped[0] as Bundle).dir);
	const manifests = new Map(
		shipped.flatMap((bundle) =>
			bundle.members.map((member) => {
				const read = JSON.parse(readFileSync(join(member.dir, "package.json"), "utf8"));
				const written: MemberManifest = {
					name: member.name,
					dir: basename(member.dir),
					exports: read.exports ?? {},
					dependencies: read.dependencies ?? {},
					...(read.peerDependencies ? { peerDependencies: read.peerDependencies } : {}),
					...(read.bin ? { bin: read.bin } : {}),
				};
				return [member.name, { bundle: basename(bundle.dir), path: member.dir, written }] as const;
			}),
		),
	);
	// Each member's entries resolve to its sources, whatever node_modules holds.
	const paths = Object.fromEntries(
		[...manifests.values()].flatMap(({ path, written }) =>
			Object.entries(written.exports).map(([key, source]) => [
				`${written.name}${key === "." ? "" : key.slice(1)}`,
				[join(path, source)],
			]),
		),
	);
	const staging = join(input.out, ".compiled");
	rmSync(input.out, { recursive: true, force: true });
	const sources = [...manifests.values()].flatMap(({ path }) =>
		globSync("src/**/*.ts", { cwd: path })
			.filter((file) => !/(^|\/)test\//.test(file) && !file.endsWith(".test.ts"))
			.map((file) => join(path, file)),
	);
	const program = ts.createProgram(sources, compiling(rootDir, staging, paths));
	const failed = ts.getPreEmitDiagnostics(program).map(where);
	if (failed.length > 0) return { built: [], problems: failed };
	program.emit();
	const problems: string[] = [];
	const built: string[] = [];
	const placed = (name: string) => {
		const found = manifests.get(name);
		return found ? { bundle: found.bundle, dir: found.written.dir } : undefined;
	};
	for (const bundle of shipped) {
		const declared = JSON.parse(readFileSync(join(bundle.dir, "package.json"), "utf8"));
		const described = aboutOf(publicNameOf(bundle.dir), declared, input.release);
		if ("problem" in described) {
			problems.push(described.problem);
			continue;
		}
		const dest = join(input.out, basename(bundle.dir));
		const members = bundle.members.map(
			(member) => manifests.get(member.name)?.written as MemberManifest,
		);
		for (const member of bundle.members) {
			const to = join(dest, basename(member.dir));
			for (const entry of globSync("**/*", { cwd: member.dir, withFileTypes: true })) {
				const file = relative(member.dir, join(entry.parentPath, entry.name));
				if (!entry.isFile() || leftOut(file)) continue;
				mkdirSync(dirname(join(to, file)), { recursive: true });
				cpSync(join(member.dir, file), join(to, file));
			}
			const compiled = join(staging, relative(rootDir, member.dir));
			for (const file of globSync("**/*.{js,d.ts}", { cwd: compiled })) {
				const kind = file.endsWith(".d.ts") ? "d.ts" : "js";
				const named = published(readFileSync(join(compiled, file), "utf8"), placed, kind);
				for (const name of named.unknown)
					problems.push(`${member.name}/${file}: ${name} is no shipped member`);
				mkdirSync(dirname(join(to, file)), { recursive: true });
				writeFileSync(join(to, file), named.text);
			}
		}
		const made = bundleManifest(
			{ dir: bundle.dir, members, about: described.about },
			input.release,
			(name) => manifests.get(name)?.bundle,
		);
		if ("problems" in made) {
			problems.push(...made.problems);
			continue;
		}
		writeFileSync(join(dest, "package.json"), `${JSON.stringify(made.manifest, null, "\t")}\n`);
		if (input.licenseFile) copyFileSync(input.licenseFile, join(dest, "LICENSE"));
		const own = basename(bundle.dir);
		writeFileSync(
			join(dest, "README.md"),
			readmeOf(publicNameOf(own), input.release, `modules/${own}`),
		);
		const targets = Object.values(
			made.manifest.exports as Record<string, Record<string, string>>,
		).flatMap((entry) => Object.values(entry));
		for (const target of targets) {
			if (!existsSync(join(dest, target)))
				problems.push(`${publicNameOf(bundle.dir)}: ${target} is not built`);
		}
		built.push(publicNameOf(bundle.dir));
		if (typeof declared.index === "string") {
			writeFileSync(join(dest, declared.index), indexOf(manifests, input.release.version));
		}
		for (const [name, entrance] of Object.entries(declared.entrances ?? {})) {
			const made = entranceOf(name, entrance as Entrance, placed, input.release);
			if ("problem" in made) {
				problems.push(made.problem);
				continue;
			}
			const at = join(input.out, basename(name));
			mkdirSync(at, { recursive: true });
			writeFileSync(join(at, "package.json"), `${JSON.stringify(made.manifest, null, "\t")}\n`);
			writeFileSync(join(at, "main.js"), made.main);
			if (input.licenseFile) copyFileSync(input.licenseFile, join(at, "LICENSE"));
			writeFileSync(join(at, "README.md"), readmeOf(name, input.release));
			built.push(name);
		}
	}
	rmSync(staging, { recursive: true, force: true });
	return { built, problems };
}
