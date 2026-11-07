#!/usr/bin/env node
/**
 * A registry of a check's own, serving the tarballs in the directories it is told, after the
 * upstream registry's address: each package's document holds every version's manifest, its
 * tarball's address, npm's integrity of its bytes, and when its directory says it was published.
 * Any other name's document is the upstream's, as it answers (a scope of its own may hold packages
 * published there). Told as one JSON argument: `upstream`, `published` (each `dir` and its `at`) and
 * `upstreamMs`; it prints its origin once listening.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { basename, join } from "node:path";

const told = JSON.parse(process.argv[2] ?? "{}") as {
	readonly upstream: string;
	readonly published: readonly { readonly dir: string; readonly at: string }[];
	readonly upstreamMs?: number;
};
const { upstream } = told;
/** How long the upstream may take to answer one request, body included: 30 seconds, unless the starter says less. */
const upstreamLimitMs = told.upstreamMs ?? 30_000;
const tarballs = new Map<string, Buffer>();
const documents = new Map<
	string,
	{ versions: Record<string, unknown>; times: Record<string, string>; latest: string }
>();
const files = told.published.flatMap(({ dir, at }) =>
	readdirSync(dir)
		.filter((f) => f.endsWith(".tgz"))
		.map((f) => ({ file: join(dir, f), at })),
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
		// An upstream that fails or is slow is answered 502, so pnpm retries a registry still up.
		try {
			const answer = await fetch(new URL((request.url ?? "/").slice(1), upstream), {
				headers: { accept: request.headers.accept ?? "application/json" },
				signal: AbortSignal.timeout(upstreamLimitMs),
			});
			const body = Buffer.from(await answer.arrayBuffer());
			response.writeHead(answer.status, { "content-type": "application/json" });
			response.end(body);
		} catch {
			response.writeHead(502, { "content-type": "application/json" });
			response.end("{}");
		}
		return;
	}
	const name = path.slice(1);
	const times = Object.values(document.times).sort();
	response.writeHead(200, { "content-type": "application/json" });
	response.end(
		JSON.stringify({
			name,
			"dist-tags": { latest: document.latest },
			versions: document.versions,
			time: { created: times.at(0), modified: times.at(-1), ...document.times },
		}),
	);
});

server.listen(0, "127.0.0.1", () => {
	const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
	for (const { file, at: published } of files) {
		const bytes = readFileSync(file);
		const manifest = JSON.parse(
			execFileSync("tar", ["-xzOf", file, "package/package.json"], { encoding: "utf8" }),
		) as { name: string; version: string };
		const at = `/${manifest.name}/-/${basename(file)}`;
		tarballs.set(at, bytes);
		const document = documents.get(manifest.name) ?? {
			versions: {},
			times: {},
			latest: manifest.version,
		};
		document.times[manifest.version] = published;
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
