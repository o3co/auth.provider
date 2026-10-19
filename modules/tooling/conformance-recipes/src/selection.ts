import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "@mod/create-app";

/**
 * The modules a generate command composes, read from the app it writes: the command a recipe
 * shows is the one its scene runs. The app is written to a directory of its own, then removed.
 */
export async function composedBy(argv: readonly string[], workspace: string): Promise<string[]> {
	const target = await mkdtemp(join(tmpdir(), "recipe-"));
	try {
		const told: string[] = [];
		const code = await run([target, "--workspace", workspace, ...argv], {
			out: () => {},
			err: (line) => told.push(line),
		});
		if (code !== 0) throw new Error(`generate ${argv.join(" ")} exited ${code}: ${told.join("")}`);
		const manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8")) as {
			dependencies?: Record<string, string>;
		};
		return Object.keys(manifest.dependencies ?? {}).filter((name) => name.startsWith("@mod/"));
	} finally {
		await rm(target, { recursive: true, force: true });
	}
}
