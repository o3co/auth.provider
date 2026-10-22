// Serves the packages of `registry-packages.json` as a registry, for pnpm itself to write the
// lockfiles beside this file. A scoped package's tarball lies at a path of the registry's own, as
// some registries serve them, so pnpm may record its address. Not run by the tests; to remake them:
//   node generate.mjs 4873 &   (prints "ready")
//   in an empty `app/` (package.json depending on @x/grant 1.2.0, @o3co/auth-provider-oauth 0.19.0
//   and zod 4.6.7, pnpm-workspace.yaml overriding the latter two to those versions, .npmrc naming
//   the registry): pnpm install --config.minimumReleaseAge=0
//   in an empty `staging/` (the .npmrc alone): pnpm add @x/grant@1.2.0 --config.minimumReleaseAge=0

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

const packages = JSON.parse(
	readFileSync(join(import.meta.dirname, "registry-packages.json"), "utf8"),
);
const port = Number(process.argv[2]);
const base = `http://127.0.0.1:${port}`;
const tarballs = new Map();
const docs = new Map();
for (const manifest of packages) {
	const dir = mkdtempSync(join(tmpdir(), "pkg-"));
	writeFileSync(join(dir, "package.json"), JSON.stringify(manifest));
	for (const [file, text] of Object.entries(manifest.__files ?? {}))
		writeFileSync(join(dir, file), text);
	delete manifest.__files;
	writeFileSync(join(dir, "package.json"), JSON.stringify(manifest));
	const out = mkdtempSync(join(tmpdir(), "out-"));
	const [packed] = JSON.parse(
		execFileSync("npm", ["pack", "--json", "--pack-destination", out], {
			cwd: dir,
			encoding: "utf8",
		}),
	);
	const bytes = readFileSync(join(out, packed.filename));
	const file = `${manifest.name.replace("/", "-")}-${manifest.version}.tgz`;
	tarballs.set(`/${manifest.name}/-/${file}`, bytes);
	const doc = docs.get(manifest.name) ?? {
		name: manifest.name,
		versions: {},
		time: {},
		"dist-tags": {},
	};
	doc.versions[manifest.version] = {
		...manifest,
		dist: {
			tarball: `${base}/${manifest.name}/-/${file}`,
			integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
			shasum: createHash("sha1").update(bytes).digest("hex"),
		},
	};
	doc.time[manifest.version] = "2026-01-01T00:00:00.000Z";
	doc.time.created = "2026-01-01T00:00:00.000Z";
	doc.time.modified = "2026-01-01T00:00:00.000Z";
	doc["dist-tags"].latest = manifest.version;
	docs.set(manifest.name, doc);
}
createServer((req, res) => {
	const path = decodeURIComponent(req.url.split("?")[0]);
	if (tarballs.has(path)) {
		res.writeHead(200, { "content-type": "application/octet-stream" });
		return res.end(tarballs.get(path));
	}
	const doc = docs.get(path.slice(1));
	if (doc) {
		res.writeHead(200, { "content-type": "application/json" });
		return res.end(JSON.stringify(doc));
	}
	res.writeHead(404);
	res.end("{}");
}).listen(port, "127.0.0.1", () => process.stdout.write("ready\n"));
