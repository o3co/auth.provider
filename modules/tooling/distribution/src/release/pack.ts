#!/usr/bin/env node
/**
 * `pnpm release-pack <dir> [--from-registry]`, after `pnpm bundles`: the release packed into the
 * directory, as `packRelease` packs it, with `publish-order.json` (the files in the order the release
 * publishes them). With `--from-registry`, each package npm already holds at this version is taken
 * from the registry instead, the index sealed again over the rest (`fetched`), and `fetched.json`
 * names them; a release published out of order stops it.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { lookedUp, takenFromRegistry } from "../fetched/fetch.ts";
import { fetchPlan } from "../fetched/plan.ts";
import { releaseOrder } from "./order/release-order.ts";
import { packRelease } from "./packing/packing.ts";

const root = process.env.INIT_CWD ?? process.cwd();
const [destination, ...flags] = process.argv.slice(2);
if (!destination) {
	console.error("release-pack: name the directory the tarballs go to");
	process.exit(2);
}
const stop = (problems: readonly string[]): never => {
	for (const problem of problems) console.error(`release-pack: ${problem}`);
	process.exit(1);
};
let given = new Map<string, string>();
let taken: { name: string; version: string; integrity: string }[] = [];
if (flags.includes("--from-registry")) {
	const read = releaseOrder(root);
	if ("problems" in read) stop(read.problems);
	else {
		const units = [...read.units.first, ...read.units.last];
		const plan = fetchPlan(read.units, lookedUp(units));
		if ("problems" in plan) stop(plan.problems);
		else {
			const versioned = plan.fetch.map((u) => ({
				...u,
				version: units.find((v) => v.dir === u.dir)?.version ?? "",
			}));
			const got = takenFromRegistry(versioned, mkdtempSync(join(tmpdir(), "release-fetched-")));
			if ("problems" in got) stop(got.problems);
			else {
				given = got.given;
				taken = versioned.map(({ name, version, integrity }) => ({ name, version, integrity }));
			}
		}
	}
}
const at = resolve(destination);
const packed = packRelease(root, at, given);
if ("problems" in packed) stop(packed.problems);
else {
	writeFileSync(
		join(at, "publish-order.json"),
		`${JSON.stringify(
			packed.tarballs.map((t) => basename(t)),
			null,
			2,
		)}\n`,
	);
	writeFileSync(join(at, "fetched.json"), `${JSON.stringify(taken, null, 2)}\n`);
	console.log(
		`release-pack: ${packed.tarballs.length} tarballs, ${taken.length} taken from the registry, the index sealed over ${packed.sealedOver}`,
	);
}
