import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface Doc {
	readonly path: string;
	readonly text: string;
}

function walk(dir: string, base = dir): string[] {
	return readdirSync(dir).flatMap((entry) => {
		if (entry === "node_modules" || entry.startsWith(".")) return [];
		const path = join(dir, entry);
		return statSync(path).isDirectory() ? walk(path, base) : [relative(base, path)];
	});
}

/** Every Markdown document in the repository, without node_modules. */
export function readDocuments(root: string): Doc[] {
	return walk(root)
		.filter((file) => file.endsWith(".md"))
		.map((file) => ({ path: join(root, file), text: readFileSync(join(root, file), "utf8") }));
}
