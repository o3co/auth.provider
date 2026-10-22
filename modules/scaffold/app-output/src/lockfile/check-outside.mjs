// What a pnpm lockfile resolves the packages outside the release to, held to what was recorded
// of them when the app was generated. This one file is both the module app-output reads and the
// script an app runs (`node check-outside.mjs` beside its lockfile), so it imports nothing of the
// workspace: only `yaml`, `semver` and node.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { parseDocument } from "yaml";

/** The most a lockfile read may hold. */
const lockBytes = 16 * 1024 * 1024;

/** A value's own entries as a map, where it is a plain object; none otherwise. Nothing inherited is read. */
const own = (value) =>
	new Map(
		value !== null && typeof value === "object" && !Array.isArray(value)
			? Object.keys(value).map((key) => [key, value[key]])
			: [],
	);

const sameMap = (a, b) =>
	a.size === b.size &&
	[...a].every(
		([key, value]) => b.has(key) && JSON.stringify(b.get(key)) === JSON.stringify(value),
	);

/** A resolution as pnpm writes it, its peers in parentheses left off. */
const bare = (resolved) => String(resolved).replace(/\(.*$/, "");

/** The name a lockfile key holds, its version and peers left off (`@s/n@1.0.0(x@1)` is `@s/n`). */
const nameOf = (key) => {
	const plain = bare(key);
	return plain.slice(0, plain.lastIndexOf("@"));
};

/**
 * What a reference resolves to: a version of the name it is listed under, a version of another
 * package (an alias, `real@1.0.0`), or something local (a link, a file, a directory).
 */
function targetOf(as, reference) {
	const plain = bare(reference);
	if (plain.includes(":")) return { local: plain };
	const at = plain.lastIndexOf("@");
	return at > 0
		? { name: plain.slice(0, at), version: plain.slice(at + 1), alias: true }
		: { name: as, version: plain, alias: false };
}

/** A declared range, or a declared alias (`npm:real@range`); none where it is neither. */
function specOf(spec) {
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
function lockOf(text) {
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

/** The origin of an http address, or none. */
const originOf = (address) => {
	try {
		const url = new URL(String(address));
		return url.protocol === "https:" || url.protocol === "http:" ? url.origin : undefined;
	} catch {
		return undefined;
	}
};

/** The origin of the registry a package is installed from: its scope's, else the default one. */
const registryOf = (registries, name) => {
	const scope = name.startsWith("@") ? name.slice(0, name.indexOf("/")) : undefined;
	return originOf(own(own(registries).get("scopes")).get(scope) ?? own(registries).get("default"));
};

/**
 * Why a package's resolution is not one from its registry: an integrity, and at most the address
 * of a tarball at the registry's origin (any path); no directory, repository or other kind.
 */
function registryRefusal(entry, name, registries) {
	const resolution = own(own(entry).get("resolution"));
	if (
		typeof resolution.get("integrity") !== "string" ||
		![...resolution.keys()].every((key) => key === "integrity" || key === "tarball")
	) {
		return `${name}: resolved from no registry`;
	}
	if (!resolution.has("tarball")) return undefined;
	const at = originOf(resolution.get("tarball"));
	const registry = registryOf(registries, name);
	return at !== undefined && at === registry
		? undefined
		: `${name}: its tarball lies at ${at ?? String(resolution.get("tarball"))}, not at its registry ${registry ?? "(none recorded)"}`;
}

/** Every reference the lockfile holds: each importer's three kinds of dependency, and each snapshot's two. */
function referencesIn(lock) {
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

/**
 * Why a package that must be one copy at one version is not: each reference to it resolves to that
 * version from a registry, under its own name, and the lockfile holds no other version or second
 * resolution of it.
 */
function oneCopyRefusals(lock, name, version, references, registries, { held = true } = {}) {
	const refusals = [];
	for (const { at, as, reference } of references) {
		const target = targetOf(as, reference);
		if (as === name && (target.local || target.alias || target.version !== version)) {
			refusals.push(`${name}: ${at} resolves it to ${bare(reference)}, not ${version}`);
		} else if (as === name && !own(lock.snapshots).has(`${name}@${reference}`)) {
			refusals.push(
				`${name}: ${at} resolves it to ${reference}, which the lockfile does not resolve`,
			);
		} else if (as !== name && target.alias && target.name === name) {
			refusals.push(`${name}: reached as ${as} by ${at}`);
		}
	}
	const versions = [...own(lock.packages).keys()]
		.filter((key) => nameOf(key) === name)
		.map((key) => bare(key).slice(name.length + 1))
		.sort();
	if (versions.some((v) => v !== version)) {
		refusals.push(
			`${name}: ${versions.join(", ")} in the lockfile, where ${version} alone is held`,
		);
	}
	if (!held) return refusals;
	const referenced = references.some(({ as }) => as === name);
	const entry = own(lock.packages).get(`${name}@${version}`);
	if (entry === undefined && referenced)
		refusals.push(`${name}: the lockfile holds no ${name}@${version}`);
	const unregistered = entry === undefined ? undefined : registryRefusal(entry, name, registries);
	if (unregistered !== undefined) refusals.push(unregistered);
	const resolved = [...own(lock.snapshots).keys()].filter((key) => nameOf(key) === name);
	if (resolved.length > 1) {
		refusals.push(
			`${name}: ${resolved.length} resolutions in the lockfile, where the app holds one`,
		);
	}
	return refusals;
}

/**
 * Why one snapshot of a recorded package does not resolve what the record declares: required
 * dependencies and peers as required, optional ones as optional (an optional dependency taking
 * the place of a required one of its name), each to a version in its range (the app's overrides
 * applied) or, where declared as an alias, to a version of the package the alias names.
 */
function snapshotRefusals(record, snapshot, overrides, say) {
	const optional = own(record.optionalDependencies);
	const required = new Map([...own(record.dependencies)].filter(([name]) => !optional.has(name)));
	const peers = own(record.peerDependencies);
	const optionalPeer = (name) =>
		own(own(record.peerDependenciesMeta).get(name)).get("optional") === true;
	const groups = [
		["dependencies", own(own(snapshot).get("dependencies"))],
		["optionalDependencies", own(own(snapshot).get("optionalDependencies"))],
	];
	const refusals = [];
	for (const [group, deps] of groups) {
		const asRequired = group === "dependencies";
		for (const [dep, reference] of deps) {
			const spec = asRequired
				? (required.get(dep) ?? (peers.has(dep) ? peers.get(dep) : undefined))
				: (optional.get(dep) ?? (peers.has(dep) && optionalPeer(dep) ? peers.get(dep) : undefined));
			if (spec === undefined) {
				const declared = required.has(dep) || optional.has(dep) || peers.has(dep);
				refusals.push(
					say(
						declared
							? `${dep} resolves as ${asRequired ? "required" : "optional"}, not as declared`
							: `depends on ${dep}, which the record does not declare`,
					),
				);
				continue;
			}
			const held = overrides.get(dep);
			const wanted = specOf(held ?? spec);
			const target = targetOf(dep, reference);
			if (wanted === undefined)
				refusals.push(say(`declares ${dep} as ${spec}, which is no registry range`));
			else if (target.local) refusals.push(say(`${dep} resolves ${target.local}, not a version`));
			else if (
				Boolean(wanted.name) !== target.alias ||
				(wanted.name && wanted.name !== target.name)
			) {
				refusals.push(
					say(
						`${dep} resolves ${bare(reference)}, not ${wanted.name ? `an alias of ${wanted.name}` : `${dep} itself`}`,
					),
				);
			} else if (!semver.valid(target.version) || !semver.satisfies(target.version, wanted.range)) {
				refusals.push(say(`${dep} resolves ${target.version}, outside ${wanted.range}`));
			}
		}
	}
	const resolved = groups[0][1];
	for (const dep of [...required.keys(), ...[...peers.keys()].filter((p) => !optionalPeer(p))]) {
		if (!resolved.has(dep)) refusals.push(say(`${dep} is declared, but not resolved as required`));
	}
	return refusals;
}

/** Why one recorded package is not what the lockfile resolves, the app's overrides applied. */
function recordRefusals(lock, record, overrides, references, registries) {
	const { name, version } = record;
	const say = (what) => `${name}: ${what}`;
	const root = own(own(own(own(lock.importers).get(".")).get("dependencies")).get(name));
	const resolved = root.get("version");
	if (resolved === undefined || bare(resolved) !== version) {
		return [
			say(
				`the app resolves ${resolved === undefined ? "nothing" : bare(resolved)}, not ${version} as recorded`,
			),
		];
	}
	if (root.get("specifier") !== version) {
		return [say(`the app depends on it as ${root.get("specifier")}, not ${version} as recorded`)];
	}
	// Not held: a recorded package may resolve more than once (each resolution is checked below), and its registry is checked here.
	const refusals = oneCopyRefusals(lock, name, version, references, registries, { held: false });
	const entry = own(lock.packages).get(`${name}@${version}`);
	const unregistered = registryRefusal(entry, name, registries);
	if (unregistered !== undefined) return [...refusals, unregistered];
	const integrity = own(own(entry).get("resolution")).get("integrity");
	if (integrity !== record.integrity) {
		return [...refusals, say(`integrity ${integrity}, not ${record.integrity} as recorded`)];
	}
	const peers = own(record.peerDependencies);
	const locked = own(own(entry).get("peerDependencies"));
	for (const dep of [...new Set([...peers.keys(), ...locked.keys()])].sort()) {
		const want = peers.has(dep) ? (overrides.get(dep) ?? peers.get(dep)) : undefined;
		if (locked.get(dep) !== want) {
			refusals.push(
				say(
					`peer ${dep} is ${locked.get(dep) ?? "none"}, not ${want ?? "none"} as recorded with the app's overrides`,
				),
			);
		}
	}
	if (!sameMap(own(own(entry).get("peerDependenciesMeta")), own(record.peerDependenciesMeta))) {
		refusals.push(say("peerDependenciesMeta is not as recorded"));
	}
	const snapshots = [...own(lock.snapshots)].filter(([key]) => nameOf(key) === name);
	if (!own(lock.snapshots).has(`${name}@${resolved}`))
		refusals.push(say("the lockfile holds no resolution of it"));
	for (const [, snapshot] of snapshots)
		refusals.push(...snapshotRefusals(record, snapshot, overrides, say));
	for (const [dep, range] of peers) {
		const held = overrides.get(dep);
		if (held !== undefined && !semver.satisfies(held, String(range))) {
			refusals.push(say(`the app holds ${dep} at ${held}, outside its peer range ${range}`));
		}
	}
	return refusals;
}

/**
 * Why the lockfile does not resolve each recorded package as recorded, with the app's `overrides`
 * (name to version) applied, why it holds an overridden package in other than one copy at its
 * version, why either comes from other than its registry in `registries` (the default origin and
 * each scope's), why it was resolved with other overrides, and why an overridden package is not the
 * tarball whose integrity the release recorded (`integrities`, one for each package the overrides
 * hold; one without refused); none where it is as recorded.
 */
export function refusals(text, records, overrides, registries, integrities) {
	const lock = lockOf(text);
	const versions = (map) =>
		new Map([...own(map)].map(([name, version]) => [name, String(version)]));
	const held = versions(overrides);
	const references = referencesIn(lock);
	const resolvedWith = versions(lock.overrides);
	return [
		...(sameMap(resolvedWith, held)
			? []
			: ["the lockfile was resolved with other overrides than the app's"]),
		...records.flatMap((record) => recordRefusals(lock, record, held, references, registries)),
		...[...held]
			.sort(([a], [b]) => (a < b ? -1 : 1))
			.flatMap(([name, version]) =>
				oneCopyRefusals(lock, name, String(version), references, registries),
			),
		...heldIntegrityRefusals(lock, held, own(integrities)),
	];
}

/**
 * Why a package the overrides hold is not the tarball the release recorded: its entry at the held
 * version (the package, not a resolution with peers) holds another integrity, or none is recorded.
 */
function heldIntegrityRefusals(lock, held, integrities) {
	return [...held]
		.sort(([a], [b]) => (a < b ? -1 : 1))
		.flatMap(([name, version]) => {
			const recorded = integrities.get(name);
			if (typeof recorded !== "string") return [`${name}: the app records no integrity of it`];
			const entry = own(lock.packages).get(`${name}@${version}`);
			if (entry === undefined) return [];
			const integrity = own(own(entry).get("resolution")).get("integrity");
			return integrity === recorded
				? []
				: [`${name}: integrity ${integrity}, not ${recorded} as the release recorded`];
		});
}

/**
 * The version and integrity a project's lockfile resolves `name` to, as its root importer depends
 * on it; refuses one the importer lacks, one resolved to no version, and one from other than its
 * registry in `registries`.
 */
export function recordOf(text, name, registries) {
	const lock = lockOf(text);
	const resolved = own(own(own(own(lock.importers).get(".")).get("dependencies")).get(name)).get(
		"version",
	);
	if (resolved === undefined) throw new Error(`${name}: the project does not depend on it`);
	const target = targetOf(name, resolved);
	if (target.local || target.alias || !semver.valid(target.version)) {
		throw new Error(`${name}: the project resolves ${bare(resolved)}, not a version`);
	}
	const entry = own(lock.packages).get(`${name}@${target.version}`);
	const unregistered = registryRefusal(entry, name, registries);
	if (unregistered !== undefined) throw new Error(unregistered);
	return {
		name,
		version: target.version,
		integrity: own(own(entry).get("resolution")).get("integrity"),
	};
}

/** Run as an app's script: the lockfile, the record (its packages and registries) and the overrides beside it. */
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const read = (file) => readFileSync(file, "utf8");
	try {
		const workspace = parseDocument(read("pnpm-workspace.yaml"), { merge: false }).toJS({
			maxAliasCount: 0,
		});
		const outside = JSON.parse(read("outside-modules.json"));
		const found = refusals(
			read("pnpm-lock.yaml"),
			outside.modules,
			Object.fromEntries(own(own(workspace).get("overrides"))),
			outside.registries,
			outside.held,
		);
		for (const line of found) process.stdout.write(`${line}\n`);
		process.stdout.write(
			found.length === 0 ? "check:outside: ok\n" : `check:outside: ${found.length} refusal(s)\n`,
		);
		process.exitCode = found.length === 0 ? 0 : 1;
	} catch (error) {
		// What cannot be read is a refusal too, said in a line.
		process.stdout.write(
			`check:outside: ${error instanceof Error ? error.message : String(error)}\n`,
		);
		process.exitCode = 1;
	}
}
