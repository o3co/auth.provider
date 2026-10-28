import { readFileSync } from "node:fs";
import { join } from "node:path";
import { importsOf, type Pkg, packageOf, type Surface } from "@mod/guard-imports";
import type { Budget } from "../contract.ts";
import { countLines } from "../source.ts";
import { budgetsAsTest, type Scope, unitsOf } from "../units.ts";

const planPhrases = ["Not yet built", "Moving to", "Moved to", "being removed"];

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
 * Each unit whose dependency cards pass `dependencyCardBytes`, with their bytes: a measure, not a
 * refusal, as they grow with cards the unit does not own.
 */
export function heavyDependencyCards(
	packages: readonly Pkg[],
	budget: Budget,
): { readonly where: string; readonly bytes: number }[] {
	return dependencyCards(packages, budget).filter((u) => u.bytes > budget.dependencyCardBytes);
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

/** One measure of a unit: what it counts, its value, and the limit G7 holds it to, where one does. */
export interface Measure {
	readonly where: string;
	readonly what: string;
	readonly value: number;
	readonly limit?: number;
}

const cardItems = (card: string) => card.split("\n").filter((l) => /^\s*- /.test(l));

/** Every measure of the package and of each internal module on its own, under its limit or past it. */
export function budgetMeasures(
	s: Scope,
	p: Pkg,
	surfaces: ReadonlyMap<string, Surface>,
): Measure[] {
	const { budget, byName, workspaceDeps } = s;
	const fixture = new RegExp(budget.fixtureFile);
	const counted = new RegExp(budget.countedFixtureFile);
	const generated = new RegExp(budget.generatedFile);
	const { cardDirs, unitOf, cardOf, whereOf } = unitsOf(p);
	return ["", ...cardDirs].flatMap((unit) => {
		const where = whereOf(unit);
		const found: Measure[] = [];
		const measure = (what: string, value: number, limit?: number) => {
			// A package's own measure where the budget makes an exception of it, with its reason.
			const excepted =
				unit === ""
					? budget.exceptions?.find((e) => e.package === p.name && e.measure === what)?.limit
					: undefined;
			const held = excepted ?? limit;
			found.push(held === undefined ? { where, what, value } : { where, what, value, limit: held });
		};
		const files = p.files.filter((file) => unitOf(file) === unit);
		let sourceLines = 0;
		let testLines = 0;
		let commentLines = 0;
		let bytes = 0;
		for (const file of files) {
			if (generated.test(file)) continue;
			if (file.endsWith(".ts") || file.endsWith(".mjs") || file.endsWith("README.md")) {
				bytes += readFileSync(join(p.dir, file)).length;
			}
		}
		const docs = surfaces.get(p.name)?.docs;
		for (const file of s.sources(p).filter((f) => unitOf(f) === unit && !generated.test(f))) {
			// The doc comments of the public surface are its contract, not comments on the implementation.
			const counts = countLines(join(p.dir, file), docs?.get(file));
			// Fixtures count as test lines; other tables, such as vectors, do not.
			if (fixture.test(file) && !counted.test(file)) continue;
			if (budgetsAsTest(s, p, file)) testLines += counts.code;
			else {
				sourceLines += counts.code;
				commentLines += counts.comment;
			}
		}
		measure("source lines", sourceLines, budget.sourceLines);
		measure("test lines", testLines, budget.testLines);
		const commentLimit = Math.max(budget.commentShare * sourceLines, budget.commentFloor);
		measure("comment lines", commentLines, Math.round(commentLimit * 10) / 10);
		if (unit === "") {
			const surface = surfaces.get(p.name);
			const common = s.isCommon(p);
			measure(
				"contract values",
				surface?.values.size ?? 0,
				common ? budget.commonContractValues : budget.contractValues,
			);
			const wider = budget.widerSurfaceKinds.includes(s.kindOf(p));
			measure(
				"contract members",
				surface?.members ?? 0,
				wider ? budget.widerContractMembers : budget.contractMembers,
			);
		}
		const card = cardOf(unit);
		if (card !== undefined) {
			const dependents = s.packages.filter((q) => workspaceDeps(q, false).includes(p.name));
			const narrow = unit === "" && dependents.length >= budget.narrowCardFanIn;
			measure(
				"card lines",
				card.split("\n").length,
				narrow ? budget.narrowCardLines : budget.cardLines,
			);
			measure("card bytes", Buffer.byteLength(card), budget.cardBytes);
			const items = cardItems(card);
			measure("card items", items.length);
			const largest = Math.max(0, ...items.map((line) => Buffer.byteLength(line)));
			measure("card item bytes", largest, budget.cardItemBytes);
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
		measure("reading scope bytes", bytes + cards, budget.readRangeBytes);
		const imported = [...importedBy(p, unit, budget)].filter((name) => {
			const dep = byName.get(name);
			return dep !== undefined && !s.isCommon(dep);
		});
		measure("dependencies", imported.length, budget.dependencies);
		return found;
	});
}

/** G7, with G9 and G17 on what it measures: the package and each internal module on its own. */
export function budgetRules(s: Scope, p: Pkg, surfaces: ReadonlyMap<string, Surface>) {
	const { budget, report } = s;
	const { cardDirs, cardOf, whereOf } = unitsOf(p);
	const byWhere = Map.groupBy(budgetMeasures(s, p, surfaces), (m) => m.where);
	for (const unit of ["", ...cardDirs]) {
		const where = whereOf(unit);
		const over = (what: string, value: number, limit: number, note = "") => {
			if (value > limit) report("G7 budget", where, `${what} ${value} > ${limit}${note}`);
		};
		for (const m of byWhere.get(where) ?? []) {
			// Each item is reported by its own opening, below.
			if (m.limit !== undefined && m.what !== "card item bytes") over(m.what, m.value, m.limit);
		}
		if (unit === "") {
			for (const type of surfaces.get(p.name)?.hidden ?? []) {
				report("G9 types in public signatures are exported", p.name, type);
			}
		}
		const card = cardOf(unit);
		if (card === undefined) {
			report("G7 budget", where, "no card");
			continue;
		}
		// Each item held to the unit's limit as measured, an exception's where the budget makes one.
		const itemLimit =
			byWhere.get(where)?.find((m) => m.what === "card item bytes")?.limit ?? budget.cardItemBytes;
		for (const line of cardItems(card)) {
			const opening = line.replace(/^\s*- /, "").slice(0, 12);
			over("card item bytes", Buffer.byteLength(line), itemLimit, ` (${opening}…)`);
		}
		for (const phrase of planPhrases) {
			if (card.includes(phrase))
				report("G17 a card holds only the current contract", where, phrase);
		}
	}
}
