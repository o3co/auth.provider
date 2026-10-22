#!/usr/bin/env node
/**
 * Before anything is published: for every tarball in the directory, what the registry holds at its
 * version must be this tarball, or nothing; any other answer stops the release, and nothing is
 * published. Run on the tarballs this run packed, or those of an earlier run restored to resume it.
 */
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { lookupOf, publishedProblems } from "./published.ts";
import { packedOf } from "./seal.ts";

const directory = process.argv[2];
if (!directory) {
	console.error("release-published: name the directory the tarballs are in");
	process.exit(2);
}
const at = resolve(directory);
const packed = readdirSync(at)
	.filter((file) => file.endsWith(".tgz"))
	.map((file) => packedOf(join(at, file)));
const lookups = new Map(
	packed.map(({ name, version }) => {
		const answer = spawnSync("npm", ["view", `${name}@${version}`, "dist.integrity", "--json"], {
			encoding: "utf8",
			timeout: 60_000,
		});
		return [
			name,
			lookupOf({
				status: answer.status ?? 1,
				stdout: answer.stdout ?? "",
				stderr: answer.stderr ?? "",
			}),
		];
	}),
);
const problems = publishedProblems(packed, lookups);
for (const problem of problems) console.error(`release-published: ${problem}`);
console.log(
	problems.length === 0
		? `release-published: ${packed.length} tarballs, none published otherwise`
		: `release-published: ${problems.length} problem(s); nothing may be published`,
);
process.exit(problems.length === 0 ? 0 : 1);
