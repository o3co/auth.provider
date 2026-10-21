import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { BootRefused } from "@mod/kernel";
import { type Config, ParseError, parse, ResolveError } from "@o3co/ts.hocon";
import { legacyVariables } from "./legacy-variables.ts";

export interface ConfigSource {
	/** Highest priority first. */
	readonly files: readonly string[];
	readonly env: Readonly<Record<string, string | undefined>>;
}

/**
 * Layers the files, highest priority first, and returns a plain tree. Resolves each file on its
 * own, then layers them, so substitutions reach only env and the same file: a refusal names the
 * file, which the HOCON library's deferred resolution does not tell. Remove when: its ResolveError
 * carries the file (`file`) after a deferred resolve; then resolve the merged layers once, so
 * substitutions cross files again.
 */
export async function loadConfig(source: ConfigSource): Promise<unknown> {
	const [first, ...rest] = await layersOf(source.files, setOf(source.env));
	if (first === undefined) return {};
	return rest.reduce((acc, layer) => acc.withFallback(layer), first).toObject();
}

/**
 * The variables 0.17 bound that `source.env` sets and no file reads, in order; never their values.
 * A file reads the names the HOCON library looks up in the env it is given, and only those.
 */
export async function unreadLegacyVariables(source: ConfigSource): Promise<readonly string[]> {
	const env = setOf(source.env);
	const read = new Set<string>();
	const noted = (name: string | symbol) => {
		if (typeof name === "string") read.add(name);
	};
	const recording = new Proxy(env, {
		get(target, name, receiver) {
			noted(name);
			return Reflect.get(target, name, receiver);
		},
		has(target, name) {
			noted(name);
			return Reflect.has(target, name);
		},
		getOwnPropertyDescriptor(target, name) {
			noted(name);
			return Reflect.getOwnPropertyDescriptor(target, name);
		},
	});
	await layersOf(source.files, recording);
	return Object.keys(env)
		.filter((name) => legacyVariables.has(name) && !read.has(name))
		.sort();
}

/** The boot's warning for the names `unreadLegacyVariables` gives: how many and which; none for none. */
export function legacyVariablesWarning(names: readonly string[]): string | undefined {
	if (names.length === 0) return undefined;
	const [count, verb] =
		names.length === 1 ? ["1 variable", "is"] : [`${names.length} variables`, "are"];
	return `${count} named in 0.17 ${verb} set and never read: ${names.join(", ")}; see docs/migration.md`;
}

const setOf = (env: ConfigSource["env"]) =>
	Object.fromEntries(
		Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined),
	);

/** Each file read and parsed on its own with `env`; one that cannot be refuses boot. */
async function layersOf(files: readonly string[], env: Record<string, string>): Promise<Config[]> {
	const layers: Config[] = [];
	for (const file of files) {
		const text = await readFile(file, "utf8").catch(() => {
			throw new BootRefused([{ where: file, reason: "cannot read the configuration file" }]);
		});
		try {
			layers.push(parse(text, { env, baseDir: dirname(file) }));
		} catch (error) {
			throw new BootRefused([refusalOf(file, error)]);
		}
	}
	return layers;
}

/** Where a file fails, at its line and column, and why by the kind of failure; never its text. */
function refusalOf(file: string, error: unknown) {
	if (error instanceof ParseError) {
		return { where: `${file}:${error.line}:${error.col}`, reason: "not readable as HOCON" };
	}
	if (error instanceof ResolveError) {
		return { where: `${file}:${error.line}:${error.col}`, reason: `cannot resolve ${error.path}` };
	}
	return { where: file, reason: "not readable as HOCON, or a substitution cannot be resolved" };
}
