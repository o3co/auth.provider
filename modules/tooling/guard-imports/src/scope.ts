import { join, relative, sep } from "node:path";
import { type FileFacts, type LexicalAnalysis, lexicalAnalysis, realOf } from "./facts/facts.ts";
import type { Pkg } from "./workspace.ts";

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
}

/** What every rule reads, and where it reports. */
export interface Scope<B extends Rules = Rules> {
	readonly packages: readonly Pkg[];
	readonly budget: B;
	readonly byName: ReadonlyMap<string, Pkg>;
	readonly report: (rule: string, where: string, detail: string) => void;
	/** A package's kind, as its manifest names it. */
	readonly kindOf: (p: Pkg) => string;
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

/**
 * A published contract test suite is test code for the budget and for the rules that pass tests by,
 * though it lives outside the test place; the other rules check it as shipped code.
 */
export function budgetsAsTest(s: Scope, p: Pkg, file: string) {
	return s.isTest(file) || file === p.manifest.exports?.["./testing"]?.replace(/^\.\//, "");
}
