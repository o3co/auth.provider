import { join } from "node:path";
import {
	importedNames,
	importRules,
	type Pkg,
	type Rules,
	type Surface,
	scopeOf,
	surfacesOf,
	type Violation,
} from "@mod/guard-imports";
import { budgetRules, dependencyCards } from "./budget/budget.ts";
import { laidOut } from "./documents.ts";
import { helpersOf, networkRules } from "./network/network.ts";
import { protocolRules } from "./protocol/protocol.ts";
import { foreignFiles, namesLine } from "./references.ts";
import { branchesOf, clockReads, commentsOf, randomReads } from "./source.ts";
import { budgetsAsTest, type Scope } from "./units.ts";
import type { Doc } from "./workspace.ts";

export { branchingImports, dependencyCards } from "./budget/budget.ts";
export type { Doc, Pkg, Violation };

/** The configuration: the budget numbers, beside the rules guard-imports reads. */
export interface Budget extends Rules {
	/** The kind of a wire's contract, held to it alone (G33). */
	readonly protocolKind: string;
	readonly readRangeBytes: number;
	readonly sourceLines: number;
	readonly testLines: number;
	readonly contractValues: number;
	readonly commonContractValues: number;
	/** The members of a package's exported interfaces and type aliases, together. */
	readonly contractMembers: number;
	/** The same, for the kinds whose contract other modules are built on. */
	readonly widerContractMembers: number;
	readonly dependencies: number;
	readonly cardLines: number;
	readonly cardBytes: number;
	/** A package that this many packages depend on at run time has its card held to the narrower lines. */
	readonly narrowCardFanIn: number;
	readonly narrowCardLines: number;
	/** Any card item's bytes, a line opening with `- `, nested ones too. */
	readonly cardItemBytes: number;
	/** The test tables that count as test lines all the same: fixtures. */
	readonly countedFixtureFile: string;
	/** The bytes of the cards of the packages a unit's shipped code imports, together. */
	readonly dependencyCardBytes: number;
	/**
	 * Comment lines, but for the doc comments of the package's public surface, may reach this share
	 * of the source lines, or the floor, whichever is more.
	 */
	readonly commentShare: number;
	readonly commentFloor: number;
	/** How many consecutive values of a configuration list a document may lay out in order. */
	readonly laidOutValues: number;
	/** Test tables (fixtures, vectors): data for tests, not counted as test lines. */
	readonly fixtureFile: string;
	/** Files a tool writes from another (a bundle): no one reads them as written, so neither their bytes nor their lines count. */
	readonly generatedFile: string;
}

const allowedExports = new Set([".", "./testing", "./module", "./audit-events"]);
/** The words a plan or a move in progress is written with; those go to the scope's list of plans. */
/** A card holds the current contract: a plan, a move or a removal under way belongs to TODO. Matched as written, so a value that moved is no move. */
/** G5, and what each source file reads: G11, G13, G15, G23; what it imports is guard-imports'. */
function sourceRules(s: Scope, p: Pkg) {
	const { budget, kindOf, report } = s;
	for (const key of Object.keys(p.manifest.exports ?? {})) {
		if (!allowedExports.has(key)) report("G5 shape of the public interface", p.name, key);
	}
	const fromKernel = budget.runtimeFromKernel.includes(kindOf(p));
	for (const file of s.sources(p)) {
		const test = s.isTest(file);
		const path = join(p.dir, file);
		const where = `${p.name}/${file}`;
		if (!test && kindOf(p) === budget.wiringKind) {
			for (const word of branchesOf(path)) {
				report("G15 wiring neither branches nor loops", where, word);
			}
		}
		if (fromKernel && !budgetsAsTest(s, p, file)) {
			for (const read of clockReads(path)) {
				report("G13 the clock comes from the kernel", where, read);
			}
			for (const read of randomReads(path)) {
				report("G23 randomness comes from the kernel", where, read);
			}
		}
		for (const comment of commentsOf(path)) {
			const found = namesLine(comment);
			if (found) report("G11 no line numbers", where, found);
		}
	}
}

/** G6: the bottom level's contract and imports (common's, protocol's) hold no name another package's contract owns. */
function commonVocabulary(s: Scope, p: Pkg, surfaces: ReadonlyMap<string, Surface>) {
	if (s.level(p) !== 0) return;
	const foreign = new Map<string, string>();
	for (const [owner, surface] of surfaces) {
		// Every other package's names, those beside it on the bottom level too; its own are its own.
		if (owner !== p.name && s.byName.has(owner)) {
			for (const name of [...surface.values, ...surface.types]) foreign.set(name, owner);
		}
	}
	const rule = "G6 the bottom level holds no name another contract owns";
	const own = surfaces.get(p.name);
	for (const name of new Set([...(own?.values ?? []), ...(own?.types ?? [])])) {
		const owner = foreign.get(name);
		if (owner) s.report(rule, `${p.name} contract`, `${name} (${owner})`);
	}
	for (const file of s.sources(p).filter((f) => !s.isTest(f))) {
		for (const name of importedNames(join(p.dir, file))) {
			const owner = foreign.get(name);
			if (owner) s.report(rule, `${p.name}/${file}`, `${name} (${owner})`);
		}
	}
}

/** G11, G12, G21 on the repository's documents. */
function documentRules(s: Scope, documents: readonly Doc[]) {
	// G21: the budget's lists of names, each flattened, as a document could copy them.
	const lists = Object.values(s.budget)
		.filter((value): value is unknown[] => Array.isArray(value))
		.map((value) => value.flat().filter((item): item is string => typeof item === "string"));
	for (const doc of documents) {
		for (const line of doc.text.split("\n")) {
			const runs = lists.map((list) => laidOut(line, list));
			const longest = runs.reduce((a, b) => (b.length > a.length ? b : a), []);
			if (longest.length > s.budget.laidOutValues) {
				s.report("G21 documents copy no configuration lists", doc.path, longest.join(", "));
			}
		}
		const found = namesLine(doc.text);
		if (found) s.report("G11 no line numbers", doc.path, found);
		for (const ref of foreignFiles(doc.path, doc.text)) {
			s.report("G12 documents point at no file in another directory", doc.path, ref);
		}
	}
}

export function check(
	packages: readonly Pkg[],
	budget: Budget,
	documents: readonly Doc[] = [],
): Violation[] {
	const violations: Violation[] = [];
	const s = scopeOf(
		packages,
		budget,
		(rule, where, detail) => violations.push({ rule, where, detail }),
		helpersOf(packages),
	);
	const surfaces = surfacesOf(packages);
	const importedCards = new Map(dependencyCards(packages, budget).map((u) => [u.where, u.bytes]));
	importRules(s, surfaces);
	for (const p of packages) {
		sourceRules(s, p);
		networkRules(s, p);
		protocolRules(s, p);
		commonVocabulary(s, p, surfaces);
		budgetRules(s, p, surfaces, importedCards);
	}
	documentRules(s, documents);
	return violations;
}
