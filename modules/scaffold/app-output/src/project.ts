/** What every generated project shares: the target's check, the manifest and the app's entries. */
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export const kernel = "@mod/kernel";
/** Where an app's entry reads its configuration files from. */
export const configFiles = "@mod/config-files";

/** An npm package name, scoped or not: what the app's imports and dependencies can name. */
const packageName = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
/** The longest name npm takes for a package, its scope included. */
const longestPackageName = 214;

/** Refuses, before anything is written, a name the app could not import or depend on. */
export function namesPackages(names: readonly string[]): void {
	for (const name of names) {
		if (!packageName.test(name) || name.length > longestPackageName) {
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
/** Where the operator writes the keys the configuration reads: each one's variable, those of several lines, and the local layer. */
export interface KeysWritten {
	readonly read: Readonly<Record<string, string>>;
	readonly severalLines: readonly string[];
	readonly local: string;
}

const noKeys: KeysWritten = { read: {}, severalLines: [], local: "config/local.conf" };

/**
 * An entry's answer to a refused boot, with `written`, which waits for what it writes to be handed
 * on, and where to write each key it reads: every entry's mark `refused`.
 */
export const refusedPart = (keys: KeysWritten = noKeys) =>
	filled("refused.ts.part", {
		keysRead: JSON.stringify(keys.read),
		severalLines: JSON.stringify(keys.severalLines),
		local: keys.local,
	});

export const mainSource = async (
	modules: readonly string[],
	importOf = (name: string) => name,
	keys: KeysWritten = noKeys,
) =>
	filled("main.ts.template", {
		refused: await refusedPart(keys),
		kernel: importOf(kernel),
		configFiles: importOf(configFiles),
		imports: modules.map((name, i) => `import m${i} from "${importOf(name)}/module";`).join("\n"),
		modules: modules.map((_, i) => `m${i}`).join(", "),
	});

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
