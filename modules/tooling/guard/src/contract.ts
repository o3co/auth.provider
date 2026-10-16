import { readFileSync } from "node:fs";
import { join } from "node:path";
import { laidOut } from "./documents.ts";
import { foreignFiles, namesLine } from "./references.ts";
import {
	branchesOf,
	clockReads,
	commentsOf,
	countLines,
	importedNames,
	importsOf,
	keyedByImports,
	randomReads,
} from "./source.ts";
import { type Surface, surfaceOf } from "./surface.ts";
import type { Doc, Pkg } from "./workspace.ts";

export type { Doc, Pkg };

export interface Budget {
	readonly readRangeBytes: number;
	readonly sourceLines: number;
	readonly testLines: number;
	readonly contractValues: number;
	readonly commonContractValues: number;
	/** The members of a package's exported interfaces and type aliases, together. */
	readonly contractMembers: number;
	/** The same, for the kinds whose contract other modules are built on. */
	readonly widerContractMembers: number;
	readonly widerSurfaceKinds: readonly string[];
	readonly dependencies: number;
	readonly cardLines: number;
	readonly cardBytes: number;
	/** A package that this many packages depend on at run time has its card held to the narrower lines. */
	readonly narrowCardFanIn: number;
	readonly narrowCardLines: number;
	/** The bytes of the cards of the packages a unit's shipped code imports, together. */
	readonly dependencyCardBytes: number;
	/** Comment lines may reach this share of the source lines, or the floor, whichever is more. */
	readonly commentShare: number;
	readonly commentFloor: number;
	/** How many consecutive values of a configuration list a document may lay out in order. */
	readonly laidOutValues: number;
	readonly testFile: string;
	/** Test tables (fixtures, vectors): data for tests, not counted as test lines. */
	readonly fixtureFile: string;
	readonly commonKind: string;
	/** Kinds whose source must take the time and randomness from the kernel's runtime, never draw them directly. */
	readonly runtimeFromKernel: readonly string[];
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

export interface Violation {
	readonly rule: string;
	readonly where: string;
	readonly detail: string;
}

const allowedExports = new Set([".", "./testing", "./module", "./audit-events"]);
/** The words a plan or a move in progress is written with; those go to the scope's list of plans. */
/** A card holds the current contract: a plan, a move or a removal under way belongs to TODO. Matched as written, so a value that moved is no move. */
const planPhrases = ["Not yet built", "Moving to", "Moved to", "being removed"];

function packageOf(specifier: string): { name: string; subpath: string } | undefined {
	if (specifier.startsWith(".") || specifier.startsWith("node:")) return undefined;
	const parts = specifier.split("/");
	const size = specifier.startsWith("@") ? 2 : 1;
	return { name: parts.slice(0, size).join("/"), subpath: parts.slice(size).join("/") };
}

/** A package's units: itself, and each internal module (a directory with a card) apart from it. */
function unitsOf(p: Pkg) {
	const cardDirs = p.files
		.filter((file) => file.endsWith("/README.md"))
		.map((file) => file.slice(0, -"/README.md".length));
	/** The innermost unit a file lies in; "" for the package itself. */
	const unitOf = (file: string) =>
		cardDirs.filter((dir) => file.startsWith(`${dir}/`)).sort((a, b) => b.length - a.length)[0] ??
		"";
	const cardOf = (unit: string) =>
		unit === "" ? p.card : readFileSync(join(p.dir, unit, "README.md"), "utf8");
	const whereOf = (unit: string) => (unit === "" ? p.name : `${p.name}/${unit}`);
	return { cardDirs, unitOf, cardOf, whereOf };
}

/** The packages a unit's shipped code imports, other than its own package. */
function importedBy(p: Pkg, unit: string, budget: Budget) {
	const { unitOf } = unitsOf(p);
	const isTest = (file: string) => new RegExp(budget.testFile).test(file);
	return new Set(
		p.files
			.filter((file) => file.endsWith(".ts") && unitOf(file) === unit && !isTest(file))
			.flatMap((file) => importsOf(join(p.dir, file)))
			.flatMap((use) => packageOf(use.specifier)?.name ?? [])
			.filter((name) => name !== p.name),
	);
}

/** For each unit, the bytes of the cards of the workspace packages its shipped code imports. */
export function dependencyCards(
	packages: readonly Pkg[],
	budget: Budget,
): { readonly where: string; readonly bytes: number }[] {
	const byName = new Map(packages.map((p) => [p.name, p]));
	return packages.flatMap((p) => {
		const { cardDirs, whereOf } = unitsOf(p);
		return ["", ...cardDirs].map((unit) => {
			const bytes = [...importedBy(p, unit, budget)].reduce(
				(sum, name) => sum + Buffer.byteLength(byName.get(name)?.card ?? ""),
				0,
			);
			return { where: whereOf(unit), bytes };
		});
	});
}

/**
 * Each internal module none of whose imports any other unit of its package shares, with what it
 * imports: a sign that it pulls in what its host does not need, and may be its own module.
 */
export function branchingImports(
	packages: readonly Pkg[],
	budget: Budget,
): { readonly where: string; readonly packages: readonly string[] }[] {
	return packages.flatMap((p) => {
		const { cardDirs, whereOf } = unitsOf(p);
		const imports = new Map(["", ...cardDirs].map((unit) => [unit, importedBy(p, unit, budget)]));
		return cardDirs.flatMap((unit) => {
			const others = [...imports]
				.filter(([other]) => other !== unit)
				.flatMap(([, set]) => [...set]);
			const own = [...(imports.get(unit) ?? [])].sort();
			const shared = own.some((name) => others.includes(name));
			return own.length > 0 && !shared ? [{ where: whereOf(unit), packages: own }] : [];
		});
	});
}

/** What every rule reads, and where it reports. */
interface Scope {
	readonly packages: readonly Pkg[];
	readonly budget: Budget;
	readonly byName: ReadonlyMap<string, Pkg>;
	readonly report: (rule: string, where: string, detail: string) => void;
	/** A package's kind, as its manifest names it. */
	readonly kindOf: (p: Pkg) => string;
	/** A kind's place in the kind order; -1 for none or an unknown one. */
	readonly level: (p: Pkg) => number;
	readonly isCommon: (p: Pkg) => boolean;
	readonly isTest: (file: string) => boolean;
	readonly sources: (p: Pkg) => string[];
	readonly workspaceDeps: (p: Pkg, dev: boolean) => string[];
}

function scopeOf(packages: readonly Pkg[], budget: Budget, report: Scope["report"]): Scope {
	const byName = new Map(packages.map((p) => [p.name, p]));
	const kindOf = (p: Pkg) => p.manifest.kind ?? "";
	const conventional = new RegExp(budget.testFile);
	return {
		packages,
		budget,
		byName,
		report,
		kindOf,
		level: (p) => budget.kindOrder.findIndex((kinds) => kinds.includes(kindOf(p))),
		isCommon: (p) => kindOf(p) === budget.commonKind,
		isTest: (file) => conventional.test(file),
		sources: (p) => p.files.filter((f) => f.endsWith(".ts") && !f.endsWith(".config.ts")),
		workspaceDeps: (p, dev) =>
			Object.keys({
				...p.manifest.dependencies,
				...(dev ? p.manifest.devDependencies : {}),
			}).filter((name) => byName.has(name)),
	};
}

/** G1 */
function cycles(s: Scope) {
	const state = new Map<string, "open" | "done">();
	const visit = (name: string, path: string[]) => {
		if (state.get(name) === "open") {
			s.report("G1 no cycles", name, [...path, name].join(" → "));
			return;
		}
		if (state.get(name) === "done") return;
		state.set(name, "open");
		const p = s.byName.get(name);
		if (p) for (const dep of s.workspaceDeps(p, true)) visit(dep, [...path, name]);
		state.set(name, "done");
	};
	for (const p of s.packages) visit(p.name, []);
}

/** G2, G10, G14, G16: what a package may depend on. */
function dependencyRules(s: Scope, p: Pkg) {
	const { budget, byName, kindOf, level, report, workspaceDeps } = s;
	if (s.isCommon(p)) {
		for (const dep of workspaceDeps(p, true)) {
			report("G2 common depends on nothing in the workspace", p.name, dep);
		}
	}
	if (level(p) < 0) report("G10 kind direction", p.name, "no kind, or an unknown kind");
	const runtime = new Set(workspaceDeps(p, false));
	for (const dep of workspaceDeps(p, true)) {
		const target = byName.get(dep) as Pkg;
		// Tests assemble, so a test may reach up to wiring, and to no other higher kind.
		const testUp = !runtime.has(dep) && kindOf(target) === budget.wiringKind;
		if (level(p) >= 0 && level(target) > level(p) && !testUp) {
			report("G10 kind direction", p.name, `a lower kind depends on a higher one: ${dep}`);
		}
	}
	// G14: a check package other check packages build on stays free of the product's modules.
	const isCheck = (q: Pkg) => kindOf(q) === budget.verificationKind;
	const builtOn = s.packages.some(
		(q) => q !== p && isCheck(q) && workspaceDeps(q, true).includes(p.name),
	);
	if (isCheck(p) && builtOn) {
		for (const dep of workspaceDeps(p, true)) {
			if (budget.productKinds.includes(kindOf(byName.get(dep) as Pkg))) {
				report("G14 a verification base depends on no product module", p.name, dep);
			}
		}
	}
	// G16: a feature never depends on a capability; its tests may use a capability's stand-in.
	if (budget.capabilityBlind.includes(kindOf(p))) {
		for (const dep of workspaceDeps(p, true)) {
			if (kindOf(byName.get(dep) as Pkg) !== budget.capabilityKind) continue;
			const beyondStandIn = s.sources(p).some((file) =>
				importsOf(join(p.dir, file)).some((use) => {
					const target = packageOf(use.specifier);
					return target?.name === dep && target.subpath !== "testing";
				}),
			);
			if (runtime.has(dep) || beyondStandIn)
				report("G16 a feature depends on no capability", p.name, dep);
		}
	}
}

/** G5, and what each source file may import and read: G3, G4, G8, G11, G13, G15, G23. */
function sourceRules(s: Scope, p: Pkg) {
	const { budget, byName, kindOf, report } = s;
	for (const key of Object.keys(p.manifest.exports ?? {})) {
		if (!allowedExports.has(key)) report("G5 shape of the public interface", p.name, key);
	}
	const runtimeDeps = new Set(
		Object.keys({ ...p.manifest.dependencies, ...p.manifest.peerDependencies }),
	);
	const exportsModule = p.manifest.exports?.["./module"] !== undefined;
	const fromKernel = budget.runtimeFromKernel.includes(kindOf(p));
	for (const file of s.sources(p)) {
		const test = s.isTest(file);
		const path = join(p.dir, file);
		const where = `${p.name}/${file}`;
		for (const use of importsOf(path)) {
			const target = packageOf(use.specifier);
			if (!target) continue;
			if (!test && exportsModule && byName.has(target.name) && target.subpath === "module") {
				report("G3 only assembly uses composition definitions", where, use.specifier);
			}
			if (!test && byName.has(target.name) && target.subpath === "testing") {
				report("G4 contract tests are used only from tests", where, use.specifier);
			}
			if (!test && !use.typeOnly && !runtimeDeps.has(target.name)) {
				report("G8 runtime dependencies as declared", where, use.specifier);
			}
		}
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

/**
 * A published contract test suite is test code for the budget, though it lives outside the test
 * place and is still checked as shipped code by every other rule.
 */
function budgetsAsTest(s: Scope, p: Pkg, file: string) {
	return s.isTest(file) || file === p.manifest.exports?.["./testing"]?.replace(/^\.\//, "");
}

/** G6: common's contract and imports hold no name another package's contract owns. */
function commonVocabulary(s: Scope, p: Pkg, surfaces: ReadonlyMap<string, Surface>) {
	if (!s.isCommon(p)) return;
	const foreign = new Map<string, string>();
	for (const [owner, surface] of surfaces) {
		const q = s.byName.get(owner);
		if (q && !s.isCommon(q)) {
			for (const name of [...surface.values, ...surface.types]) foreign.set(name, owner);
		}
	}
	const rule = "G6 no feature vocabulary in common";
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

/** G7, with G9 and G17 on what it measures: the package and each internal module on its own. */
function budgetRules(
	s: Scope,
	p: Pkg,
	surfaces: ReadonlyMap<string, Surface>,
	importedCards: ReadonlyMap<string, number>,
) {
	const { budget, byName, report, workspaceDeps } = s;
	const fixture = new RegExp(budget.fixtureFile);
	const { cardDirs, unitOf, cardOf, whereOf } = unitsOf(p);
	for (const unit of ["", ...cardDirs]) {
		const where = whereOf(unit);
		const over = (what: string, value: number, limit: number) => {
			if (value > limit) report("G7 budget", where, `${what} ${value} > ${limit}`);
		};
		const files = p.files.filter((file) => unitOf(file) === unit);
		let sourceLines = 0;
		let testLines = 0;
		let commentLines = 0;
		let bytes = 0;
		for (const file of files) {
			if (file.endsWith(".ts") || file.endsWith("README.md")) {
				bytes += readFileSync(join(p.dir, file)).length;
			}
		}
		for (const file of s.sources(p).filter((f) => unitOf(f) === unit)) {
			const counts = countLines(join(p.dir, file));
			if (fixture.test(file)) continue;
			if (budgetsAsTest(s, p, file)) testLines += counts.code;
			else {
				sourceLines += counts.code;
				commentLines += counts.comment;
			}
		}
		over("source lines", sourceLines, budget.sourceLines);
		over("test lines", testLines, budget.testLines);
		const commentLimit = Math.max(budget.commentShare * sourceLines, budget.commentFloor);
		over("comment lines", commentLines, Math.round(commentLimit * 10) / 10);
		if (unit === "") {
			const surface = surfaces.get(p.name);
			over(
				"contract values",
				surface?.values.size ?? 0,
				s.isCommon(p) ? budget.commonContractValues : budget.contractValues,
			);
			const wider = budget.widerSurfaceKinds.includes(s.kindOf(p));
			over(
				"contract members",
				surface?.members ?? 0,
				wider ? budget.widerContractMembers : budget.contractMembers,
			);
			for (const type of surface?.hidden ?? []) {
				report("G9 types in public signatures are exported", p.name, type);
			}
		}
		const card = cardOf(unit);
		if (card === undefined) report("G7 budget", where, "no card");
		else {
			const dependents = s.packages.filter((q) => workspaceDeps(q, false).includes(p.name));
			const narrow = unit === "" && dependents.length >= budget.narrowCardFanIn;
			over(
				"card lines",
				card.split("\n").length,
				narrow ? budget.narrowCardLines : budget.cardLines,
			);
			over("card bytes", Buffer.byteLength(card), budget.cardBytes);
			for (const phrase of planPhrases) {
				if (card.includes(phrase))
					report("G17 a card holds only the current contract", where, phrase);
			}
		}
		// What working in the unit reads: its own files, the cards of the modules it lies in, and
		// the cards of the packages it depends on (the package's, or those its files import).
		const lying = cardDirs.filter((dir) => unit !== dir && unit.startsWith(`${dir}/`));
		const above = unit === "" ? [] : [p.card ?? "", ...lying.map((dir) => cardOf(dir) ?? "")];
		const reached =
			unit === ""
				? workspaceDeps(p, false)
				: [
						...new Set(
							files
								.filter((file) => file.endsWith(".ts"))
								.flatMap((file) => importsOf(join(p.dir, file)))
								.map((use) => packageOf(use.specifier)?.name ?? "")
								.filter((name) => name !== p.name && byName.has(name)),
						),
					];
		const cards = [...above, ...reached.map((d) => byName.get(d)?.card ?? "")].reduce(
			(sum, text) => sum + Buffer.byteLength(text),
			0,
		);
		over("reading scope bytes", bytes + cards, budget.readRangeBytes);
		over("dependency cards", importedCards.get(where) ?? 0, budget.dependencyCardBytes);
		const imported = [...importedBy(p, unit, budget)].filter((name) => {
			const dep = byName.get(name);
			return dep !== undefined && !s.isCommon(dep);
		});
		over("dependencies", imported.length, budget.dependencies);
	}
}

/** G22, G24: which packages wire a feature's store interface, and how. */
function wiringRules(s: Scope) {
	const { kindOf, report } = s;
	const g22 = "G22 only wiring wires, and a feature that declares storeWiring has one";
	const isWiring = (p: Pkg) => kindOf(p) === s.budget.wiringKind;
	const wired = new Set(s.packages.filter(isWiring).map((p) => p.manifest.wires));
	for (const p of s.packages) {
		if (p.manifest.wires !== undefined && !isWiring(p))
			report(g22, p.name, `kind ${kindOf(p) || "none"}`);
		if (p.manifest.storeWiring && !wired.has(p.name)) report(g22, p.name, "no package wires it");
	}
	// G24: a wiring keys its guarantees by the needs its feature declares, so the feature declares them.
	for (const w of s.packages.filter(isWiring)) {
		const feature = w.manifest.wires;
		if (feature === undefined) continue;
		const keyed = s
			.sources(w)
			.filter((file) => !s.isTest(file))
			.some((file) => keyedByImports(join(w.dir, file), feature).length > 0);
		if (!keyed) {
			report(
				"G24 a wired feature declares its store's needs",
				feature,
				`${w.name} keys no guarantee by them`,
			);
		}
	}
}

/** G25: an adapter serves one axis of a workspace owner, an axis has one default, and optIn is a feature's. */
function axisRules(s: Scope) {
	const { kindOf, report } = s;
	const g25 = "G25 an adapter serves one axis, with one default, and only a feature opts in";
	const axes = new Map<string, Pkg[]>();
	for (const p of s.packages) {
		const { replaces, adapts, joins } = p.manifest;
		const isAdapter = kindOf(p) === s.budget.adapterKind;
		if (isAdapter && replaces !== undefined && adapts !== undefined) {
			report(g25, p.name, "declares replaces and adapts");
		} else if (isAdapter && replaces === undefined && adapts === undefined) {
			report(g25, p.name, "declares neither replaces nor adapts");
		} else if (isAdapter) {
			const owner = String(replaces ?? adapts);
			if (!s.byName.has(owner)) report(g25, p.name, `names no workspace package: ${owner}`);
			else axes.set(owner, [...(axes.get(owner) ?? []), p]);
			// Wording comes with its axis as the default, so it never also joins its owner as a bridge.
			const wording = s
				.sources(p)
				.some(
					(file) =>
						!s.isTest(file) && readFileSync(join(p.dir, file), "utf8").includes("mailTemplates"),
				);
			if (wording && Array.isArray(joins) && joins.includes(owner)) {
				report(g25, p.name, "joins the owner it adapts");
			}
		}
		const flag = (key: "default" | "optIn", kind: string) => {
			const value = p.manifest[key];
			if (value === undefined) return;
			if (kindOf(p) !== kind) report(g25, p.name, `${key} on kind ${kindOf(p) || "none"}`);
			else if (value !== true) report(g25, p.name, `${key} is not true`);
		};
		flag("default", s.budget.adapterKind);
		flag("optIn", s.budget.featureKind);
	}
	for (const [owner, adapters] of axes) {
		const defaults = adapters.filter((p) => p.manifest.default === true).length;
		if (defaults > 1) report(g25, owner, `${defaults} defaults among its adapters`);
		if (adapters.length > 1 && defaults === 0) {
			report(g25, owner, `no default among its ${adapters.length} adapters`);
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
	const s = scopeOf(packages, budget, (rule, where, detail) =>
		violations.push({ rule, where, detail }),
	);
	const surfaces = new Map<string, Surface>();
	for (const p of packages) {
		const entry = p.manifest.exports?.["."];
		if (entry) surfaces.set(p.name, surfaceOf(join(p.dir, entry), p.dir));
	}
	const importedCards = new Map(dependencyCards(packages, budget).map((u) => [u.where, u.bytes]));
	cycles(s);
	for (const p of packages) {
		dependencyRules(s, p);
		sourceRules(s, p);
		commonVocabulary(s, p, surfaces);
		budgetRules(s, p, surfaces, importedCards);
	}
	wiringRules(s);
	axisRules(s);
	documentRules(s, documents);
	return violations;
}
