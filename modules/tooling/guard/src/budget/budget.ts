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

/** G7, with G9 and G17 on what it measures: the package and each internal module on its own. */
export function budgetRules(
	s: Scope,
	p: Pkg,
	surfaces: ReadonlyMap<string, Surface>,
	importedCards: ReadonlyMap<string, number>,
) {
	const { budget, byName, report, workspaceDeps } = s;
	const fixture = new RegExp(budget.fixtureFile);
	const counted = new RegExp(budget.countedFixtureFile);
	const generated = new RegExp(budget.generatedFile);
	const { cardDirs, unitOf, cardOf, whereOf } = unitsOf(p);
	for (const unit of ["", ...cardDirs]) {
		const where = whereOf(unit);
		const over = (what: string, value: number, limit: number, note = "") => {
			if (value > limit) report("G7 budget", where, `${what} ${value} > ${limit}${note}`);
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
			for (const line of card.split("\n").filter((l) => /^\s*- /.test(l))) {
				const opening = line.replace(/^\s*- /, "").slice(0, 12);
				over("card item bytes", Buffer.byteLength(line), budget.cardItemBytes, ` (${opening}…)`);
			}
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
