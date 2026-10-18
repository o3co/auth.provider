import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { type Config, ParseError, parse, ResolveError } from "@o3co/ts.hocon";
import { BootRefused } from "./refusal.ts";

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
	const env = Object.fromEntries(
		Object.entries(source.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
	);
	const layers: Config[] = [];
	for (const file of source.files) {
		const text = await readFile(file, "utf8").catch(() => {
			throw new BootRefused([{ where: file, reason: "cannot read the configuration file" }]);
		});
		try {
			layers.push(parse(text, { env, baseDir: dirname(file) }));
		} catch (error) {
			throw new BootRefused([refusalOf(file, error)]);
		}
	}
	const [first, ...rest] = layers;
	if (first === undefined) return {};
	return rest.reduce((acc, layer) => acc.withFallback(layer), first).toObject();
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
