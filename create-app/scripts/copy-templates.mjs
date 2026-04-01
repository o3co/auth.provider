import { cpSync, rmSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = resolve(__dirname, "../../templates/standalone");
const dest = resolve(__dirname, "../templates/standalone");

rmSync(dest, { recursive: true, force: true });
cpSync(src, dest, {
	recursive: true,
	filter: (source) => {
		// Exclude node_modules, dist, and test directories
		return !source.includes("node_modules") && !source.includes("/dist/");
	},
});
