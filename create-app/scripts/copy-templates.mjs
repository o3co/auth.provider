import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = resolve(__dirname, "../../templates/standalone");
const dest = resolve(__dirname, "../templates/standalone");

const EXCLUDED_DIRS = new Set(["node_modules", "dist"]);

rmSync(dest, { recursive: true, force: true });
cpSync(src, dest, {
	recursive: true,
	filter: (source) => {
		const segments = source.split(sep);
		return !segments.some((segment) => EXCLUDED_DIRS.has(segment));
	},
});

// Embed the core package version so it's available at runtime without
// traversing the monorepo source tree (which won't exist in published tarballs).
const corePkgPath = resolve(__dirname, "../../packages/core/package.json");
const corePkg = JSON.parse(readFileSync(corePkgPath, "utf-8"));
const version = corePkg.version ?? "0.0.0";

writeFileSync(resolve(dest, "..", "core-version.json"), `${JSON.stringify({ version })}\n`);
