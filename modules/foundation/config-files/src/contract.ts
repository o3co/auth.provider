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
	return names.length === 0 ? undefined : `${namedIn017(names)}; see docs/migration.md`;
}

/** How many and which, in the warning's words and the refusal's. */
function namedIn017(names: readonly string[]): string {
	const [count, verb] =
		names.length === 1 ? ["1 variable", "is"] : [`${names.length} variables`, "are"];
	return `${count} named in 0.17 ${verb} set and never read: ${names.join(", ")}`;
}

/** The variable an app's entry reads to choose what the check does: `warn` (unset), `refuse` or `ignore`. */
const modeVariable = "APP_LEGACY_VARIABLES";

/**
 * The boot's check for 0.17's variables left in `source.env`, as `APP_LEGACY_VARIABLES` there says:
 * unset or `warn`, the warning `legacyVariablesWarning` gives, or none; `refuse`, a refused boot
 * naming them where any is set; `ignore`, nothing, as nothing is read. Any other value refuses boot
 * at the variable, never showing it. The names come in order, never their values.
 */
export async function legacyVariablesCheck(source: ConfigSource): Promise<string | undefined> {
	const mode = source.env[modeVariable] ?? "warn";
	if (mode === "ignore") return undefined;
	if (mode !== "warn" && mode !== "refuse") {
		throw new BootRefused([{ where: modeVariable, reason: "one of warn, refuse or ignore" }]);
	}
	const names = await unreadLegacyVariables(source);
	if (mode === "warn" || names.length === 0) return legacyVariablesWarning(names);
	throw new BootRefused([
		{
			where: "config-files",
			reason: `${namedIn017(names)}; remove them, or set ${modeVariable} to warn or ignore; see docs/migration.md`,
		},
	]);
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
