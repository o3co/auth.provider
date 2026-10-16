/** What every generated project shares: the target's check, the workspace's packages and the app's entry. */
import { execFileSync } from "node:child_process";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export const kernel = "@mod/kernel";

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

/** Package directories by name, as the workspace definition places them. */
export function workspacePackages(root: string): Map<string, string> {
	const listed = JSON.parse(
		execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], { cwd: root, encoding: "utf8" }),
	) as { name: string; path: string }[];
	return new Map(listed.map((entry) => [entry.name, entry.path]));
}

/** Each name's dependency: a link to its workspace directory when given a workspace, else any version. */
export function dependenciesOf(
	names: readonly string[],
	known: ReadonlyMap<string, string> | undefined,
): Record<string, string> {
	const dependencies: Record<string, string> = {};
	for (const name of names) {
		const dir = known?.get(name);
		if (known && !dir) throw new Error(`${name} is not in the workspace`);
		dependencies[name] = dir ? `link:${dir}` : "*";
	}
	return dependencies;
}

/** The project's manifest, starting the app with `start`. */
/** The pnpm the workspace builds with, so the lockfile reads alike in the image. */
const pnpm = "pnpm@11.3.0";

export const manifestOf = (start: string, dependencies: Record<string, string>, reseal?: string) =>
	`${JSON.stringify(
		{
			name: "auth-provider-app",
			private: true,
			type: "module",
			packageManager: pnpm,
			scripts: reseal === undefined ? { start } : { start, reseal },
			dependencies,
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
		imports: modules.map((name, i) => `import m${i} from "${importOf(name)}/module";`).join("\n"),
		modules: modules.map((_, i) => `m${i}`).join(", "),
	});

/** The app's reseal entry, for an app that composes `seal`: the same modules, built and never started. */
export const resealSource = (modules: readonly string[], importOf = (name: string) => name) =>
	filled("reseal.ts.template", {
		kernel: importOf(kernel),
		seal: importOf(sealPackage),
		imports: modules.map((name, i) => `import m${i} from "${importOf(name)}/module";`).join("\n"),
		modules: modules.map((_, i) => `m${i}`).join(", "),
	});

/** The package whose resealers the reseal entry runs. */
export const sealPackage = "@mod/seal";

export const withKernel = (modules: readonly string[]) => [
	kernel,
	...modules.filter((name) => name !== kernel),
];

/** Writes every file, by its path in the project, once all are made: nothing is written for a project that fails. */
export async function writeProject(target: string, files: Readonly<Record<string, string>>) {
	for (const [path, text] of Object.entries(files)) {
		await mkdir(dirname(join(target, path)), { recursive: true });
		await writeFile(join(target, path), text);
	}
}
