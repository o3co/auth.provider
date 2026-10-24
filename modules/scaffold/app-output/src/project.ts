/** What every generated project shares: the target's check, the manifest and the app's entries. */
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export const kernel = "@mod/kernel";
/** Where an app's entry reads its configuration files from. */
export const configFiles = "@mod/config-files";

/** An npm package name, scoped or not: what the app's imports and dependencies can name. */
const packageName = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;

/** Refuses, before anything is written, a name the app could not import or depend on. */
export function namesPackages(names: readonly string[]): void {
	for (const name of names) {
		if (!packageName.test(name) || name.length > 214) {
			throw new Error(`${name} is not a package name`);
		}
	}
}

/** A reading's catch: a missing file or directory reads as `absent`, and any other failure is thrown on. */
export const missingAs =
	<T>(absent: T) =>
	(error: NodeJS.ErrnoException): T => {
		if (error.code === "ENOENT") return absent;
		throw error;
	};

/** A target that is missing or empty; one that holds anything is refused, never overwritten. */
export async function vacant(target: string): Promise<void> {
	const held = await readdir(target).catch(missingAs([]));
	if (held.length > 0) throw new Error(`${target} is not empty`);
}

/** The pnpm the workspace builds with, so the lockfile reads alike in the image. */
const pnpm = "pnpm@11.28.7";

/** The zod the packages take, so a section the app writes is read by the same copy. */
export const zod = "4.6.7";

/** The project's manifest, starting the app with `start`, and running each of `scripts` by its name. */
export const manifestOf = (
	start: string,
	dependencies: Record<string, string>,
	scripts: Readonly<Record<string, string>> = {},
) =>
	`${JSON.stringify(
		{
			name: "auth-provider-app",
			private: true,
			type: "module",
			packageManager: pnpm,
			scripts: { start, ...scripts },
			dependencies: { ...dependencies, zod },
		},
		null,
		"\t",
	)}\n`;

/** Fills a file of `templates/` by its `{{name}}` marks; a mark with no value stays as written. */
export async function filled(template: string, fill: Readonly<Record<string, string>>) {
	const text = await readFile(join(import.meta.dirname, "..", "templates", template), "utf8");
	return text.replace(/\{\{(\w+)\}\}/g, (all, key: string) => fill[key] ?? all);
}

/** The app's entry, importing each module under what `importOf` names it (the workspace's name, unless published). */
export const mainSource = (modules: readonly string[], importOf = (name: string) => name) =>
	filled("main.ts.template", {
		kernel: importOf(kernel),
		configFiles: importOf(configFiles),
		imports: modules.map((name, i) => `import m${i} from "${importOf(name)}/module";`).join("\n"),
		modules: modules.map((_, i) => `m${i}`).join(", "),
	});

/**
 * The app's entries besides `start`, each for an app that composes its package: the same modules,
 * built and never started, running what that package offers. The template's mark `entry` names it;
 * a backfill's marks `contract` and `answers` name the contract it settles through and the answers
 * it counts, in the order its line tells them.
 */
const entries: readonly {
	readonly script: string;
	readonly file: string;
	readonly template: string;
	readonly runs: string;
	readonly fill?: Readonly<Record<string, string>>;
}[] = [
	{ script: "reseal", file: "src/reseal.ts", template: "reseal.ts.template", runs: "@mod/seal" },
	{
		script: "witness-backfill",
		file: "src/witness-backfill.ts",
		template: "backfill.ts.template",
		runs: "@mod/mfa-witnessing",
		fill: {
			contract: "witnessBackfill",
			answers: '"marked", "held", "none", "unclaimed", "inconsistent"',
		},
	},
];

/**
 * The scripts and files of the entries the composed modules call for; `run` writes the command
 * that runs a file, as the project starts its app.
 */
export async function entriesOf(
	modules: readonly string[],
	importOf: (name: string) => string,
	run: (file: string) => string,
) {
	const called = entries.filter((entry) => modules.includes(entry.runs));
	const files: Record<string, string> = {};
	for (const entry of called) {
		files[entry.file] = await filled(entry.template, {
			...entry.fill,
			kernel: importOf(kernel),
			configFiles: importOf(configFiles),
			entry: importOf(entry.runs),
			imports: modules.map((name, i) => `import m${i} from "${importOf(name)}/module";`).join("\n"),
			modules: modules.map((_, i) => `m${i}`).join(", "),
		});
	}
	const scripts = Object.fromEntries(called.map((entry) => [entry.script, run(entry.file)]));
	return { scripts, files };
}

export const withKernel = (modules: readonly string[]) => [
	kernel,
	configFiles,
	...modules.filter((name) => name !== kernel && name !== configFiles),
];

/** Writes every file, by its path in the project, once all are made: nothing is written for a project that fails. */
export async function writeProject(target: string, files: Readonly<Record<string, string>>) {
	for (const [path, text] of Object.entries(files)) {
		await mkdir(dirname(join(target, path)), { recursive: true });
		await writeFile(join(target, path), text);
	}
}
