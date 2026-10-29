#!/usr/bin/env node
/**
 * Where the release publishes, before its draft is made: the release's notes, written from the
 * version's section of the workspace's changelog; a version it cannot take them for stops the release.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { notesOf } from "./notes.ts";

const [version, out] = process.argv.slice(2);
if (!version || !out) {
	console.error("release-notes: name the version, and the file to write its notes to");
	process.exit(2);
}
const root = process.env.INIT_CWD ?? process.cwd();
const taken = notesOf(readFileSync(join(root, "CHANGELOG.md"), "utf8"), version);
if ("problem" in taken) {
	console.error(`release-notes: ${taken.problem}`);
	process.exit(1);
}
writeFileSync(resolve(root, out), taken.notes);
console.log(`release-notes: ${version}'s notes, from CHANGELOG.md`);
