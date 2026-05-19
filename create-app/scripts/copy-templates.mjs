import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = resolve(__dirname, "../../templates/standalone");
const dest = resolve(__dirname, "../templates/standalone");

const EXCLUDED_DIRS = new Set(["node_modules", "dist"]);

// NOTE: `reference.conf` is intentionally NOT copied here. It lives in
// `packages/core/config/reference.conf` and is shipped to consumers via the
// `@o3co/auth-provider-core` package's `exports` field (`./reference.conf`
// subpath export, files: ["config", ...]). Consumers and the standalone
// composition root resolve it at boot via
// `import.meta.resolve("@o3co/auth-provider-core/reference.conf")`.
// The template's `config/` directory contains only consumer-facing files
// (`application.conf`, `development.conf`, `production.conf`) — the
// per-deployment delta layer, not the library baseline.

// Mirrors `shouldCopyTemplateEntry` in src/internal/template-filter.mts: only
// segments INSIDE `src` are checked against EXCLUDED_DIRS, not the absolute
// install-prefix path above it. Without this, running the prebuild script with
// the workspace itself living under a `node_modules` directory would copy zero
// files. (This script runs at build time before tsc, so it cannot import the
// compiled module — the logic is duplicated by necessity.)
const shouldCopy = (source) => {
	if (source === src) return true;
	const prefix = src.endsWith(sep) ? src : `${src}${sep}`;
	if (!source.startsWith(prefix)) return true;
	const rel = source.slice(prefix.length);
	return !rel.split(sep).some((segment) => EXCLUDED_DIRS.has(segment));
};

rmSync(dest, { recursive: true, force: true });
cpSync(src, dest, {
	recursive: true,
	filter: shouldCopy,
});

// Embed package versions so they're available at runtime without
// traversing the monorepo source tree (which won't exist in published tarballs).
const readVersion = (pkgPath) => {
	const pkg = JSON.parse(readFileSync(resolve(__dirname, pkgPath), "utf-8"));
	return pkg.version ?? "0.0.0";
};

const versions = {
	"@o3co/auth-provider-core": readVersion("../../packages/core/package.json"),
	"@o3co/auth-provider-dpop": readVersion("../../packages/dpop/package.json"),
	"@o3co/auth-provider-mtls": readVersion("../../packages/mtls/package.json"),
	"@o3co/auth-provider-federation-google": readVersion(
		"../../packages/federation-google/package.json",
	),
	"@o3co/auth-provider-federation-github": readVersion(
		"../../packages/federation-github/package.json",
	),
	"@o3co/auth-provider-oauth": readVersion("../../packages/oauth/package.json"),
	"@o3co/auth-provider-oauth-token-exchange": readVersion(
		"../../packages/oauth-token-exchange/package.json",
	),
	"@o3co/auth-provider-session": readVersion("../../packages/session/package.json"),
	"@o3co/auth-provider-foundation": readVersion("../../packages/foundation/package.json"),
	"@o3co/auth-provider-redis": readVersion("../../packages/redis/package.json"),
	"@o3co/auth-provider-webauthn": readVersion("../../packages/webauthn/package.json"),
};

writeFileSync(resolve(dest, "..", "versions.json"), `${JSON.stringify(versions, null, "\t")}\n`);
