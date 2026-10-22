#!/usr/bin/env node
/**
 * Packs every package the release publishes into the destination, the index sealed in between:
 * the bundles but the one holding the index, then the index sealed with their integrity and zod's,
 * then the index's bundle and the entrances. Run after `pnpm bundles`.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { readBundles } from "../contract.ts";
import { packOrder } from "./pack-order.ts";
import { packedOf, sealed, zodOf } from "./seal.ts";

const root = process.env.INIT_CWD ?? process.cwd();
const destination = process.argv[2];
if (!destination) {
	console.error("release-pack: name the directory the tarballs go to");
	process.exit(2);
}
const out = join(root, "dist", "bundles");
if (!existsSync(out)) {
	console.error("release-pack: dist/bundles is missing; run pnpm bundles first");
	process.exit(2);
}
const into = resolve(destination);
mkdirSync(into, { recursive: true });

const declared = readBundles(root).flatMap((bundle) => {
	const manifest = JSON.parse(readFileSync(join(bundle.dir, "package.json"), "utf8"));
	return [
		{
			dir: basename(bundle.dir),
			shipped: bundle.shipped === true,
			index: manifest.index,
			entrances: Object.keys(manifest.entrances ?? {}),
		},
	];
});
const order = packOrder(
	readdirSync(out).filter((dir) => existsSync(join(out, dir, "package.json"))),
	declared,
);
if ("problem" in order) {
	console.error(`release-pack: ${order.problem}`);
	process.exit(1);
}

/** Packs one built package, with stdin closed so no lifecycle script reads it, answering the tarball. */
const pack = (dir: string) => {
	const said = execFileSync("pnpm", ["pack", "--pack-destination", into], {
		cwd: join(out, dir),
		encoding: "utf8",
		stdio: ["ignore", "pipe", "inherit"],
	});
	const named = said.trim().split("\n").at(-1) ?? "";
	return named.startsWith("/") ? named : join(into, named);
};

const first = order.first.map(pack);
const indexFile = join(out, order.index.dir, order.index.file);
const result = sealed(
	JSON.parse(readFileSync(indexFile, "utf8")),
	order.first.map((dir) => JSON.parse(readFileSync(join(out, dir, "package.json"), "utf8")).name),
	first.map(packedOf),
	zodOf(readFileSync(join(root, "pnpm-lock.yaml"), "utf8")),
);
if ("problems" in result) {
	for (const problem of result.problems) console.error(`release-pack: ${problem}`);
	process.exit(1);
}
writeFileSync(indexFile, JSON.stringify(result.index));
const last = order.last.map(pack);
console.log(
	`release-pack: ${first.length + last.length} packed, the index sealed over ${first.length}`,
);
