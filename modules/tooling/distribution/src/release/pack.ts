#!/usr/bin/env node
/** `pnpm release-pack <dir>`, after `pnpm bundles`: the release packed into the directory, as `packRelease` packs it. */
import { resolve } from "node:path";
import { packRelease } from "./packing.ts";

const root = process.env.INIT_CWD ?? process.cwd();
const destination = process.argv[2];
if (!destination) {
	console.error("release-pack: name the directory the tarballs go to");
	process.exit(2);
}
const packed = packRelease(root, resolve(destination));
if ("problems" in packed) {
	for (const problem of packed.problems) console.error(`release-pack: ${problem}`);
	process.exit(1);
}
console.log(
	`release-pack: ${packed.tarballs.length} packed, the index sealed over ${packed.sealedOver}`,
);
