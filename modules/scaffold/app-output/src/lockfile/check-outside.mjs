// What a pnpm lockfile resolves the packages outside the release to, held to what was recorded
// of them when the app was generated. This one file is both the module app-output reads and the
// script an app runs (`node check-outside.mjs` beside its lockfile), so it imports nothing of the
// workspace: only `yaml`, `semver` and node.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { parse } from "yaml";

/** A resolution as pnpm writes it, its peers in parentheses left off. */
const bare = (resolved) => String(resolved).replace(/\(.*$/, "");

/** The name a lockfile key holds, its version and peers left off (`@s/n@1.0.0(x@1)` is `@s/n`). */
const nameOf = (key) => {
	const plain = bare(key);
	return plain.slice(0, plain.lastIndexOf("@"));
};

/** A record's peers and dependencies, each a map of names to ranges. */
const mapOf = (value) => (value && typeof value === "object" ? value : {});

const sameJson = (a, b) => JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));
const sorted = (value) =>
	value && typeof value === "object" && !Array.isArray(value)
		? Object.fromEntries(
				Object.keys(value)
					.sort()
					.map((key) => [key, sorted(value[key])]),
			)
		: value;

/** The lockfile as data, refused where it is not pnpm's version 9. */
function lockOf(text) {
	const lock = parse(text) ?? {};
	if (String(lock.lockfileVersion) !== "9.0") {
		throw new Error(`lockfile version ${lock.lockfileVersion}, where 9.0 is read`);
	}
	return lock;
}

/** A resolution from a registry holds its integrity alone: no tarball, directory or repository. */
const fromRegistry = (entry) => {
	const resolution = entry?.resolution;
	return resolution !== undefined && Object.keys(resolution).join() === "integrity";
};

/**
 * The version and integrity a project's lockfile resolves `name` to, as its root importer depends
 * on it; refuses one the importer lacks, one resolved to no version, and one from no registry.
 */
export function recordOf(text, name) {
	const lock = lockOf(text);
	const resolved = lock.importers?.["."]?.dependencies?.[name]?.version;
	if (resolved === undefined) throw new Error(`${name}: the project does not depend on it`);
	const version = bare(resolved);
	if (!semver.valid(version)) {
		throw new Error(`${name}: the project resolves ${version}, not a version`);
	}
	const entry = lock.packages?.[`${name}@${version}`];
	if (!fromRegistry(entry)) throw new Error(`${name}: resolved from no registry`);
	return { name, version, integrity: entry.resolution.integrity };
}

/** Why one recorded package is not what the lockfile resolves, the app's overrides applied. */
function recordRefusals(lock, record, overrides) {
	const { name, version } = record;
	const say = (what) => `${name}: ${what}`;
	const resolved = lock.importers?.["."]?.dependencies?.[name]?.version;
	if (resolved === undefined || bare(resolved) !== version) {
		return [
			say(
				`the app resolves ${resolved === undefined ? "nothing" : bare(resolved)}, not ${version} as recorded`,
			),
		];
	}
	const entry = lock.packages?.[`${name}@${version}`];
	if (!fromRegistry(entry)) return [say("resolved from no registry")];
	if (entry.resolution.integrity !== record.integrity) {
		return [say(`integrity ${entry.resolution.integrity}, not ${record.integrity} as recorded`)];
	}
	const refusals = [];
	const peers = mapOf(record.peerDependencies);
	/** What the lockfile holds for a range: pnpm writes an override in its place. */
	const expected = (dep, range) => overrides[dep] ?? range;
	const locked = mapOf(entry.peerDependencies);
	for (const dep of [...new Set([...Object.keys(peers), ...Object.keys(locked)])].sort()) {
		const want = peers[dep] === undefined ? undefined : expected(dep, peers[dep]);
		if (locked[dep] !== want) {
			refusals.push(
				say(
					`peer ${dep} is ${locked[dep] ?? "none"}, not ${want ?? "none"} as recorded with the app's overrides`,
				),
			);
		}
	}
	if (!sameJson(mapOf(entry.peerDependenciesMeta), mapOf(record.peerDependenciesMeta))) {
		refusals.push(say("peerDependenciesMeta is not as recorded"));
	}
	const declared = {
		...mapOf(record.optionalDependencies),
		...peers,
		...mapOf(record.dependencies),
	};
	const snapshot = lock.snapshots?.[`${name}@${resolved}`] ?? {};
	const deps = { ...mapOf(snapshot.optionalDependencies), ...mapOf(snapshot.dependencies) };
	for (const [dep, to] of Object.entries(deps).sort(([a], [b]) => (a < b ? -1 : 1))) {
		if (declared[dep] === undefined) {
			refusals.push(say(`depends on ${dep}, which the record does not declare`));
			continue;
		}
		const at = bare(to);
		const range = expected(dep, declared[dep]);
		if (!semver.valid(at)) refusals.push(say(`${dep} resolves ${at}, not a version`));
		else if (!semver.satisfies(at, range))
			refusals.push(say(`${dep} resolves ${at}, outside ${range}`));
	}
	for (const dep of Object.keys(mapOf(record.dependencies)).sort()) {
		if (deps[dep] === undefined) refusals.push(say(`${dep} is declared, but not resolved`));
	}
	for (const [dep, range] of Object.entries(peers)) {
		const held = overrides[dep];
		if (held !== undefined && !semver.satisfies(held, range)) {
			refusals.push(say(`the app holds ${dep} at ${held}, outside its peer range ${range}`));
		}
	}
	return refusals;
}

/** Why the lockfile holds a package the overrides hold to one in more than one copy, or under another name. */
function heldRefusals(lock, held) {
	const refusals = [];
	for (const name of held) {
		const versions = Object.keys(lock.packages ?? {})
			.filter((key) => nameOf(key) === name)
			.map((key) => bare(key).slice(name.length + 1))
			.sort();
		if (versions.length > 1) {
			refusals.push(
				`${name}: ${versions.length} versions in the lockfile (${versions.join(", ")}), where the app holds one`,
			);
		}
		const resolutions = Object.keys(lock.snapshots ?? {}).filter((key) => nameOf(key) === name);
		if (resolutions.length > 1) {
			refusals.push(
				`${name}: ${resolutions.length} resolutions in the lockfile, where the app holds one`,
			);
		}
	}
	const by = [
		...Object.entries(lock.importers ?? {}).map(([at, importer]) => [
			at,
			importer.dependencies,
			true,
		]),
		...Object.entries(lock.snapshots ?? {}).flatMap(([at, snapshot]) => [
			[at, snapshot?.dependencies, false],
			[at, snapshot?.optionalDependencies, false],
		]),
	];
	for (const [at, deps, importer] of by) {
		for (const [as, to] of Object.entries(mapOf(deps))) {
			const target = importer ? to?.version : to;
			for (const name of held) {
				if (as !== name && String(target ?? "").startsWith(`${name}@`)) {
					refusals.push(`${name}: reached as ${as} by ${at}`);
				}
			}
		}
	}
	return refusals;
}

/**
 * Why the lockfile does not resolve each recorded package as recorded, the app's `overrides`
 * (name to version) applied, and why it holds an overridden package in more than one copy; none
 * where it does.
 */
export function refusals(text, records, overrides) {
	const lock = lockOf(text);
	return [
		...records.flatMap((record) => recordRefusals(lock, record, overrides)),
		...heldRefusals(lock, Object.keys(overrides).sort()),
	];
}

/** Run as an app's script: the lockfile, the record and the overrides beside it. */
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const read = (file) => readFileSync(file, "utf8");
	const found = refusals(
		read("pnpm-lock.yaml"),
		JSON.parse(read("outside-modules.json")).modules,
		mapOf(parse(read("pnpm-workspace.yaml"))?.overrides),
	);
	for (const line of found) process.stdout.write(`${line}\n`);
	process.stdout.write(
		found.length === 0 ? "check:outside: ok\n" : `check:outside: ${found.length} refusal(s)\n`,
	);
	process.exitCode = found.length === 0 ? 0 : 1;
}
