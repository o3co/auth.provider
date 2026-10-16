import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { type Config, parse } from "@o3co/ts.hocon";
import { BootRefused } from "./refusal.ts";

export interface ConfigSource {
	/** Highest priority first. */
	readonly files: readonly string[];
	readonly env: Readonly<Record<string, string | undefined>>;
}

/**
 * Layers the files, highest priority first, and returns a plain tree. Resolves each file on its
 * own, then layers them: deferred resolution across the layers turns objects inside arrays into
 * null in the HOCON library, so substitutions reach only env and the same file. Remove when: the
 * library's deferred resolution keeps array objects; then resolve the merged layers once so
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
		} catch {
			throw new BootRefused([
				{ where: file, reason: "not readable as HOCON, or a substitution cannot be resolved" },
			]);
		}
	}
	const [first, ...rest] = layers;
	if (first === undefined) return {};
	return rest.reduce((acc, layer) => acc.withFallback(layer), first).toObject();
}
