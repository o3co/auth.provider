#!/usr/bin/env node
/**
 * A registry of the release check's own, serving the tarballs in the directories named after the
 * upstream registry's address: each package's document holds every version's manifest, its
 * tarball's address and npm's integrity of its bytes, each published two days before, so no
 * `minimumReleaseAge` holds it back. Any other name's document is the upstream's, as it answers
 * (a scope of its own may hold packages published there). It prints its origin once listening.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { basename, join } from "node:path";

const published = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
const tarballs = new Map<string, Buffer>();
const documents = new Map<string, { versions: Record<string, unknown>; latest: string }>();
const [upstream = "", ...dirs] = process.argv.slice(2);
const files = dirs.flatMap((dir) =>
	readdirSync(dir)
		.filter((f) => f.endsWith(".tgz"))
		.map((f) => join(dir, f)),
);

const server = createServer(async (request, response) => {
	const path = decodeURIComponent((request.url ?? "/").split("?")[0] ?? "/");
	const tarball = tarballs.get(path);
	if (tarball) {
		response.writeHead(200, { "content-type": "application/octet-stream" });
		response.end(tarball);
		return;
	}
	const document = documents.get(path.slice(1));
	if (!document) {
		const answer = await fetch(new URL((request.url ?? "/").slice(1), upstream), {
			headers: { accept: request.headers.accept ?? "application/json" },
		});
		response.writeHead(answer.status, { "content-type": "application/json" });
		response.end(Buffer.from(await answer.arrayBuffer()));
		return;
	}
	const name = path.slice(1);
	const time = Object.fromEntries(Object.keys(document.versions).map((v) => [v, published]));
	response.writeHead(200, { "content-type": "application/json" });
	response.end(
		JSON.stringify({
			name,
			"dist-tags": { latest: document.latest },
			versions: document.versions,
			time: { created: published, modified: published, ...time },
		}),
	);
});

server.listen(0, "127.0.0.1", () => {
	const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
	for (const file of files) {
		const bytes = readFileSync(file);
		const manifest = JSON.parse(
			execFileSync("tar", ["-xzOf", file, "package/package.json"], { encoding: "utf8" }),
		) as { name: string; version: string };
		const at = `/${manifest.name}/-/${basename(file)}`;
		tarballs.set(at, bytes);
		const document = documents.get(manifest.name) ?? { versions: {}, latest: manifest.version };
		document.versions[manifest.version] = {
			...manifest,
			dist: {
				tarball: `${origin}${at}`,
				integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
				shasum: createHash("sha1").update(bytes).digest("hex"),
			},
		};
		documents.set(manifest.name, document);
	}
	process.stdout.write(`${origin}\n`);
});
