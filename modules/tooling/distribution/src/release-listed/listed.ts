#!/usr/bin/env node
/**
 * Where the release publishes, before anything is published: the tarballs in the directory must be
 * those the lists were made of, by the lists' `tarballs.json`; any other stops it, and nothing is
 * published. It reads the tarballs alone, and runs nothing they hold.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { packedOf } from "../packed/packed.ts";
import { listedProblems } from "./problems.ts";

const [directory, listing] = process.argv.slice(2);
if (!directory || !listing) {
	console.error(
		"release-listed: name the directory the tarballs are in, and the lists' tarballs.json",
	);
	process.exit(2);
}
const at = resolve(directory);
const tarballs = readdirSync(at)
	.filter((file) => file.endsWith(".tgz"))
	.map((file) => ({ ...packedOf(join(at, file)), file }));
const problems = listedProblems(tarballs, JSON.parse(readFileSync(resolve(listing), "utf8")));
for (const problem of problems) console.error(`release-listed: ${problem}`);
console.log(
	problems.length === 0
		? `release-listed: ${tarballs.length} tarballs, those the lists were made of`
		: `release-listed: ${problems.length} problem(s); nothing may be published`,
);
process.exit(problems.length === 0 ? 0 : 1);
