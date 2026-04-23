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

// Embed package versions so they're available at runtime without
// traversing the monorepo source tree (which won't exist in published tarballs).
const readVersion = (pkgPath) => {
	const pkg = JSON.parse(readFileSync(resolve(__dirname, pkgPath), "utf-8"));
	return pkg.version ?? "0.0.0";
};

const versions = {
	"@o3co/auth-provider-core": readVersion("../../packages/core/package.json"),
	"@o3co/auth-provider-did": readVersion("../../packages/did/package.json"),
	"@o3co/auth-provider-federation-google": readVersion(
		"../../packages/federation-google/package.json",
	),
	"@o3co/auth-provider-federation-github": readVersion(
		"../../packages/federation-github/package.json",
	),
	"@o3co/auth-provider-oauth": readVersion("../../packages/oauth/package.json"),
	"@o3co/auth-provider-session": readVersion("../../packages/session/package.json"),
	"@o3co/auth-provider-foundation": readVersion("../../packages/foundation/package.json"),
};

writeFileSync(resolve(dest, "..", "versions.json"), `${JSON.stringify(versions, null, "\t")}\n`);
