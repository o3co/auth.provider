// A pnpm lockfile read as data, and the words of its keys and references: what every check of
// one reads it with. It imports nothing of the workspace: only `yaml`, `semver` and node.
import semver from "semver";
import { parseDocument } from "yaml";

/** The most a lockfile read may hold. */
export const lockBytes = 16 * 1024 * 1024;

/** A value's own entries as a map, where it is a plain object; none otherwise. Nothing inherited is read. */
export const own = (value) =>
	new Map(
		value !== null && typeof value === "object" && !Array.isArray(value)
			? Object.keys(value).map((key) => [key, value[key]])
			: [],
	);

/** A resolution as pnpm writes it, its peers in parentheses left off. */
export const bare = (resolved) => String(resolved).replace(/\(.*$/, "");

/** The name a lockfile key holds, its version and peers left off (`@s/n@1.0.0(x@1)` is `@s/n`). */
export const nameOf = (key) => {
	const plain = bare(key);
	return plain.slice(0, plain.lastIndexOf("@"));
};

/**
 * What a reference resolves to: a version of the name it is listed under, a version of another
 * package (an alias, `real@1.0.0`), or something local (a link, a file, a directory).
 */
export function targetOf(as, reference) {
	const plain = bare(reference);
	if (plain.includes(":")) return { local: plain };
	const at = plain.lastIndexOf("@");
	return at > 0
		? { name: plain.slice(0, at), version: plain.slice(at + 1), alias: true }
		: { name: as, version: plain, alias: false };
}

/** A declared range, or a declared alias (`npm:real@range`); none where it is neither. */
export function specOf(spec) {
	const text = String(spec);
	if (text.startsWith("npm:")) {
		const aliased = text.slice(4);
		const at = aliased.lastIndexOf("@");
		const range = at > 0 ? aliased.slice(at + 1) : "*";
		const name = at > 0 ? aliased.slice(0, at) : aliased;
		return semver.validRange(range) ? { name, range } : undefined;
	}
	return semver.validRange(text) ? { range: text } : undefined;
}

/** The lockfile as data: pnpm's version 9, no anchor resolved, no unknown tag, within its bound. */
export function lockOf(text) {
	if (Buffer.byteLength(text) > lockBytes) throw new Error(`lockfile over ${lockBytes} bytes`);
	const doc = parseDocument(text, { merge: false, uniqueKeys: true });
	const [problem] = [...doc.errors, ...doc.warnings];
	if (problem) throw new Error(`lockfile not read: ${problem.message.split("\n")[0]}`);
	const lock = doc.toJS({ maxAliasCount: 0 });
	if (own(lock).get("lockfileVersion") !== "9.0") {
		throw new Error(`lockfile version ${own(lock).get("lockfileVersion")}, where 9.0 is read`);
	}
	return lock;
}

/** Every reference the lockfile holds: each importer's three kinds of dependency, and each snapshot's two. */
export function referencesIn(lock) {
	const found = [];
	for (const [at, importer] of own(lock.importers)) {
		for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
			for (const [as, dep] of own(own(importer).get(group))) {
				found.push({ at: `the importer ${at}`, as, reference: String(own(dep).get("version")) });
			}
		}
	}
	for (const [at, snapshot] of own(lock.snapshots)) {
		for (const group of ["dependencies", "optionalDependencies"]) {
			for (const [as, reference] of own(own(snapshot).get(group))) {
				found.push({ at, as, reference: String(reference) });
			}
		}
	}
	return found;
}
