import { join, relative, sep } from "node:path";
import {
	type Edge,
	type FileFacts,
	type LexicalAnalysis,
	lexicalAnalysis,
	realOf,
} from "../facts/facts.ts";
import type { Pkg } from "../workspace.ts";

/** The kinds' order and roles, in the words the caller gives them. */
export interface Kinds {
	readonly commonKind: string;
	/** Kinds whose source must take the time and randomness from the kernel's runtime, never draw them directly. */
	readonly runtimeFromKernel: readonly string[];
	/** The kinds whose contract other modules are built on, measured more widely. */
	readonly widerSurfaceKinds: readonly string[];
	/** The kind that serves an axis, and the kind a deployment may leave off. */
	readonly adapterKind: string;
	readonly featureKind: string;
	/** Kinds from the bottom up; a kind may depend on its own level and those below. */
	readonly kindOrder: readonly (readonly string[])[];
	/** The kind of the packages that check the product from outside. */
	readonly verificationKind: string;
	/** The kinds of the product's own modules, which a base for checks must not depend on. */
	readonly productKinds: readonly string[];
	/** The kind whose source only wires an interface to a capability, so it never branches or loops. */
	readonly wiringKind: string;
	/** The kind of the general capabilities that only wiring may depend on, among the product. */
	readonly capabilityKind: string;
	/** Kinds that must reach a capability through wiring, never depend on one. */
	readonly capabilityBlind: readonly string[];
}

/** What the rules read beside the workspace: the kinds, and where a test file lies. */
export interface Rules extends Kinds {
	readonly testFile: string;
	/** How many packages must state a property they hold to declaration (G32); none where unset. */
	readonly declaredProperties?: number;
	/** The entries every package may have, which none keeps for named takers (G5's). */
	readonly standardEntries: readonly string[];
}

/** The keys naming an entry in a package's `takenBy`: those it keeps for named takers, and each other with why it is not. */
export interface TakenEntries {
	readonly kept: readonly string[];
	readonly notKept: readonly { readonly key: string; readonly why: string }[];
}

/** What every rule reads, and where it reports. */
export interface Scope<B extends Rules = Rules> {
	readonly packages: readonly Pkg[];
	readonly budget: B;
	readonly byName: ReadonlyMap<string, Pkg>;
	readonly report: (rule: string, where: string, detail: string) => void;
	/** A package's kind, as its manifest names it. */
	readonly kindOf: (p: Pkg) => string;
	/**
	 * The owner an adapter serves: its one `adapts` or `replaces`, read of the adapter kind alone;
	 * none for a package of another kind, or one declaring both or neither.
	 */
	readonly ownerServed: (p: Pkg) => string | undefined;
	/**
	 * The keys of a package's `takenBy` naming an entry (`.`, `./…`): kept where one plain segment
	 * (`./name`), none of the standard entries, naming its takers as a non-empty list of names, and
	 * exported as one file; any other key with why not, unreported, for the rule reading it to refuse.
	 */
	readonly takenEntries: (p: Pkg) => TakenEntries;
	/** A kind's place in the kind order; -1 for none or an unknown one. */
	readonly level: (p: Pkg) => number;
	readonly isCommon: (p: Pkg) => boolean;
	readonly isTest: (file: string) => boolean;
	readonly sources: (p: Pkg) => string[];
	/** What a manifest declares: its workspace dependencies, and dev ones where asked. */
	readonly workspaceDeps: (p: Pkg, dev: boolean) => string[];
	/** What a source file is seen to say: its facts, read by one lexical program over every package's sources. */
	readonly factsOf: (p: Pkg, file: string) => FileFacts;
	/** The package whose directory holds a path, links followed; none outside every package. */
	readonly ownerOf: (path: string) => Pkg | undefined;
}

const keptKey = /^\.\/[a-z][a-z0-9-]*$/;

export function scopeOf<B extends Rules>(
	packages: readonly Pkg[],
	budget: B,
	report: Scope["report"],
	/** Files beside the sources a rule reads facts of (a fork's helper), read by the same program. */
	alsoRead: readonly string[] = [],
): Scope<B> {
	const byName = new Map(packages.map((p) => [p.name, p]));
	const kindOf = (p: Pkg) => p.manifest.kind ?? "";
	const conventional = new RegExp(budget.testFile);
	const sources = (p: Pkg) =>
		p.files.filter((f) => (f.endsWith(".ts") && !f.endsWith(".config.ts")) || f.endsWith(".mjs"));
	let analysis: LexicalAnalysis | undefined;
	// Deepest first, so a package inside another's directory owns its own files.
	const homes = packages
		.map((p) => ({ p, dir: realOf(p.dir) }))
		.sort((x, y) => y.dir.length - x.dir.length);
	return {
		packages,
		budget,
		byName,
		report,
		kindOf,
		ownerServed: (p) => {
			if (kindOf(p) !== budget.adapterKind) return undefined;
			const { adapts, replaces } = p.manifest;
			if ((adapts === undefined) === (replaces === undefined)) return undefined;
			return String(replaces ?? adapts);
		},
		takenEntries: (p) => takenEntriesOf(p, budget.standardEntries),
		level: (p) => budget.kindOrder.findIndex((kinds) => kinds.includes(kindOf(p))),
		isCommon: (p) => kindOf(p) === budget.commonKind,
		isTest: (file) => conventional.test(file),
		sources,
		// A peer is a run-time dependency, as G8 takes it.
		workspaceDeps: (p, dev) =>
			Object.keys({
				...p.manifest.dependencies,
				...p.manifest.peerDependencies,
				...(dev ? p.manifest.devDependencies : {}),
			}).filter((name) => byName.has(name)),
		factsOf: (p, file) => {
			analysis ??= lexicalAnalysis([
				...packages.flatMap((q) => sources(q).map((f) => join(q.dir, f))),
				...alsoRead,
			]);
			return analysis.factsOf(join(p.dir, file));
		},
		ownerOf: (path) => {
			const real = realOf(path);
			return homes.find(({ dir }) => {
				const into = relative(dir, real);
				return into !== ".." && !into.startsWith(`..${sep}`) && !into.startsWith(sep);
			})?.p;
		},
	};
}

/** Why an entry named in `takenBy` is none the package keeps; nothing where it keeps it. */
function whyNotKept(p: Pkg, key: string, takers: unknown, standard: readonly string[]) {
	if (standard.includes(key)) return "a reserved entry is kept for no taker";
	if (!keptKey.test(key)) return "an entry kept is one plain segment, ./name";
	const named = Array.isArray(takers) && takers.every((taker) => typeof taker === "string");
	if (!named) return "takenBy names packages as a list of names";
	if (takers.length === 0) return "an entry kept names at least one taker";
	const file = (p.manifest.exports as Record<string, unknown> | undefined)?.[key];
	if (file === undefined) return "no entry of that name";
	if (typeof file !== "string") return "an entry kept is exported as one file";
	return undefined;
}

function takenEntriesOf(p: Pkg, standard: readonly string[]): TakenEntries {
	const declared = p.manifest.takenBy;
	const kept: string[] = [];
	const notKept: { key: string; why: string }[] = [];
	if (typeof declared !== "object" || declared === null || Array.isArray(declared)) {
		return { kept, notKept };
	}
	for (const [key, takers] of Object.entries(declared)) {
		if (!key.startsWith(".")) continue;
		const why = whyNotKept(p, key, takers, standard);
		if (why === undefined) kept.push(key);
		else notKept.push({ key, why });
	}
	return { kept, notKept };
}

/** Every file an export names, each by its path in the package: a string, or each string target of a conditional export. */
function exportFiles(value: unknown): string[] {
	if (typeof value === "string") return [value.replace(/^\.\//, "")];
	if (typeof value !== "object" || value === null) return [];
	return Object.values(value).flatMap(exportFiles);
}

/** Whether an edge loads its target or takes types from it: every edge but one that only names a file (a resolve). */
const loadsOrTypes = (edge: Edge) =>
	edge.loads ||
	edge.form === "import-type" ||
	(edge.bindings.length > 0 && edge.bindings.every((binding) => binding.typeOnly));

/** A file that may hold imports, whichever the language: one the graph cannot read unless it is a source. */
const script = /\.[cm]?[jt]sx?$/;

/**
 * The package's own sources its imports reach from `roots` by the edges `follows` takes, each by its
 * path in the package; and whether the walk met what it cannot read: an import the graph cannot
 * resolve (`facts`' resolve tells why), or a script of the package, a root among them, no source.
 */
function reached(
	s: Scope,
	p: Pkg,
	roots: readonly string[],
	follows: (edge: Edge) => boolean,
): { files: Set<string>; unresolved: boolean } {
	const byReal = new Map(s.sources(p).map((file) => [realOf(join(p.dir, file)), file]));
	const known = new Set(byReal.values());
	const files = new Set<string>();
	let unresolved = roots.some((root) => script.test(root) && !known.has(root));
	const next = roots.filter((root) => known.has(root));
	for (let file = next.pop(); file !== undefined; file = next.pop()) {
		if (files.has(file)) continue;
		files.add(file);
		for (const edge of s.factsOf(p, file).edges) {
			if (!follows(edge)) continue;
			if (edge.target.kind === "unresolved") unresolved = true;
			const to = edge.target.kind === "file" ? byReal.get(edge.target.path) : undefined;
			if (to !== undefined && !files.has(to)) next.push(to);
			const target = edge.target.kind === "file" ? edge.target.path : "";
			if (to === undefined && script.test(target) && s.ownerOf(target) === p) unresolved = true;
		}
	}
	return { files, unresolved };
}

const testOnlyBy = new WeakMap<Scope, Map<string, ReadonlySet<string>>>();

/**
 * The files a package's `./testing` reaches and nothing else in it does: no other export, and no file
 * not named a test that `./testing` does not reach. `./testing` is walked by the edges that load or
 * take types, the shipped roots by every edge, a resolve too: either way a file falls to shipped.
 * None where the shipped walk meets an import the graph cannot resolve or a script of the package
 * that is no source (a root too), or `./testing` is conditional, failing closed. Read once a scope; beyond a file named as a test, no path decides it.
 */
function testOnlyOf(s: Scope, p: Pkg): ReadonlySet<string> {
	const byPackage = testOnlyBy.get(s) ?? new Map<string, ReadonlySet<string>>();
	testOnlyBy.set(s, byPackage);
	const known = byPackage.get(p.name);
	if (known !== undefined) return known;
	const exports = (p.manifest.exports ?? {}) as Record<string, unknown>;
	const testingRoot = exports["./testing"];
	// A conditional `./testing` names no one root: the package has no test root, failing closed.
	const testing =
		typeof testingRoot === "string"
			? reached(s, p, exportFiles(testingRoot), loadsOrTypes).files
			: new Set<string>();
	// Shipped: every other export, and every file not named a test that `./testing` does not reach.
	const others = Object.entries(exports).filter(([key]) => key !== "./testing");
	const loose = s.sources(p).filter((file) => !s.isTest(file) && !testing.has(file));
	const roots = [...others.flatMap(([, value]) => exportFiles(value)), ...loose];
	const shipped = reached(s, p, roots, () => true);
	const testOnly = shipped.unresolved
		? new Set<string>()
		: new Set([...testing].filter((file) => !shipped.files.has(file)));
	byPackage.set(p.name, testOnly);
	return testOnly;
}

/**
 * Test code for the budgets and for the rules on the clock, randomness, network, audit recording and
 * owned properties: a file named as a test, or one its package's `./testing` reaches by an import that
 * loads or takes types and nothing else in the package does (a published contract test suite, its
 * internal modules among it).
 * Every other file is shipped, as is every file of a package whose shipped files hold an import the
 * graph cannot resolve or reach a script of the package that is no source. A file outside the graph (a template, a bundle) is read by its name alone.
 */
export function budgetsAsTest(s: Scope, p: Pkg, file: string) {
	return s.isTest(file) || testOnlyOf(s, p).has(file);
}
