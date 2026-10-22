/** The lockfile check as one file holding the code it uses, so an app runs it without code from the install it checks. Made in development alone: the release ships the file it writes. */
import { join } from "node:path";
import { rolldown } from "rolldown";

/** The check as written, and as bundled with `yaml` and `semver` inside: the file an app runs. */
export const sourceFile = join(import.meta.dirname, "..", "check-outside.mjs");
export const bundledFile = join(import.meta.dirname, "..", "check-outside.bundled.mjs");
/** Where the bundle's paths are told from, whatever directory it is made in: the package's own. */
const packageDir = join(import.meta.dirname, "..", "..", "..");

/** Said at the top of the bundle: generated, so neither linted, formatted nor its imports sorted. */
const generatedHeader = [
	"// biome-ignore-all lint: generated from check-outside.mjs by write-check.ts, yaml and semver inside",
	"// biome-ignore-all format: generated; do not edit",
	"// biome-ignore-all assist: generated",
	"",
].join("\n");

/** The bundle of the check: its imports of `yaml` and `semver` taken in, node's builtins left to node. */
export async function bundledCheck(): Promise<string> {
	const build = await rolldown({
		input: sourceFile,
		cwd: packageDir,
		platform: "node",
		logLevel: "silent",
	});
	const { output } = await build.generate({ format: "esm", minify: false });
	await build.close();
	const [chunk] = output;
	if (chunk === undefined || chunk.type !== "chunk" || output.length !== 1) {
		throw new Error("the check did not bundle into one file");
	}
	return `${generatedHeader}${chunk.code}`;
}
