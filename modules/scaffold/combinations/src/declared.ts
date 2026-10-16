import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** What one package declares that composing reads. */
export interface Package {
	readonly name: string;
	readonly kind?: string;
	/** Whether it can be composed: it exports `./module`. */
	readonly module: boolean;
	/** The packages it needs to run (`dependencies`, not `devDependencies`). */
	readonly needs: readonly string[];
	readonly optIn: boolean;
	/** The axis owner it replaces or adapts to, and whether it is that axis's default. */
	readonly replaces?: string;
	readonly adapts?: string;
	readonly default: boolean;
}

export interface Declared {
	/** Each feature's wirings, by the feature's name. */
	readonly wirings: ReadonlyMap<string, readonly string[]>;
	readonly bridges: readonly { readonly joins: readonly string[]; readonly bridge: string }[];
	/** Every package, by name, in code point order of name. */
	readonly packages: ReadonlyMap<string, Package>;
}

interface Manifest {
	readonly name: string;
	readonly kind?: unknown;
	readonly exports?: unknown;
	readonly dependencies?: unknown;
	readonly optIn?: unknown;
	readonly replaces?: unknown;
	readonly adapts?: unknown;
	readonly default?: unknown;
	readonly wires?: unknown;
	readonly joins?: unknown;
}

const packageOf = (m: Manifest): Package => ({
	name: m.name,
	...(isName(m.kind) ? { kind: m.kind } : {}),
	module: typeof m.exports === "object" && m.exports !== null && "./module" in m.exports,
	needs:
		typeof m.dependencies === "object" && m.dependencies !== null
			? Object.keys(m.dependencies)
			: [],
	optIn: m.optIn === true,
	...(isName(m.replaces) ? { replaces: m.replaces } : {}),
	...(isName(m.adapts) ? { adapts: m.adapts } : {}),
	default: m.default === true,
});

const isName = (value: unknown): value is string => typeof value === "string" && value !== "";
const isNames = (value: unknown): value is string[] =>
	Array.isArray(value) && value.length > 0 && value.every(isName);

/**
 * What the packages of the workspace rooted at `root` declare in their package.json, as the
 * workspace definition lists them: a wiring names the feature it `wires`, a bridge the modules it
 * `joins`, a non-empty list of names; any other `wires` or `joins` is refused. Each list is in
 * code point order of name.
 */
export function declaredIn(root: string): Declared {
	const listed = JSON.parse(
		execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], { cwd: root, encoding: "utf8" }),
	) as { path: string }[];
	return declaredOf(
		listed.map(({ path }) => JSON.parse(readFileSync(join(path, "package.json"), "utf8"))),
	);
}

/** The same, from the index a bundle carries: each member's manifest as the workspace wrote it. */
export function declaredInIndex(file: string): Declared {
	const index = JSON.parse(readFileSync(file, "utf8")) as { packages: { manifest: Manifest }[] };
	return declaredOf(index.packages.map(({ manifest }) => manifest));
}

function declaredOf(manifests: readonly Manifest[]): Declared {
	const packages = [...manifests].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
	// Refused, never left missing with no word why: a bridge joining nothing would come with all.
	const misdeclared = (key: "joins" | "wires", ok: (value: unknown) => boolean, shape: string) => {
		const names = packages.filter((m) => m[key] !== undefined && !ok(m[key])).map((m) => m.name);
		return names.length > 0 ? [`${names.join(", ")}: ${key} is not ${shape}`] : [];
	};
	const refusals = [
		...misdeclared("joins", isNames, "a non-empty list of module names"),
		...misdeclared("wires", isName, "a module name"),
	];
	if (refusals.length > 0) throw new Error(refusals.join("; "));
	const wirings = new Map<string, string[]>();
	for (const { name, wires } of packages) {
		if (isName(wires)) wirings.set(wires, [...(wirings.get(wires) ?? []), name]);
	}
	const bridges = packages.flatMap(({ name, joins }) =>
		isNames(joins) ? [{ joins, bridge: name }] : [],
	);
	return { wirings, bridges, packages: new Map(packages.map((m) => [m.name, packageOf(m)])) };
}

/**
 * The modules given, then the wirings and bridges declared for them, each once and in the order
 * first named. What is brought in is completed in turn, until nothing more comes.
 */
export function completedWith(declared: Declared, modules: readonly string[]): string[] {
	const all = [...modules];
	const add = (name: string) => {
		if (!all.includes(name)) all.push(name);
	};
	for (let size = -1; size !== all.length; ) {
		size = all.length;
		for (const name of all) for (const wiring of declared.wirings.get(name) ?? []) add(wiring);
		for (const { joins, bridge } of declared.bridges) {
			if (joins.every((m) => all.includes(m))) add(bridge);
		}
	}
	return all;
}
