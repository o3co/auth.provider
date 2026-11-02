import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

/** A directory holding these files, by path relative to it. */
export function tree(files: Record<string, string>): string {
	const root = mkdtempSync(join(tmpdir(), "api-docs-"));
	for (const [path, text] of Object.entries(files)) {
		mkdirSync(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), text);
	}
	return root;
}

/** A bundle's manifest, with these exports. */
export const manifest = (name: string, exports: Record<string, unknown>, more = {}) =>
	JSON.stringify({ name, version: "0.19.2", exports, ...more });
