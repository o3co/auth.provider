import { join } from "node:path";
import type { Budget, Violation } from "../contract.ts";
import { countLines } from "../source.ts";
import { budgetsAsTest, scopeOf, unitsOf } from "../units.ts";
import type { Pkg } from "../workspace.ts";

/**
 * The limits measured before they are refused, each place over one: a card item (a line opening
 * with `- `, nested ones too) past its bytes, and a unit's test lines with its `test/fixtures`
 * counted. Each turns into a G7 limit once none is over.
 */
export function pendingLimits(packages: readonly Pkg[], budget: Budget): Violation[] {
	const found: Violation[] = [];
	const s = scopeOf(packages, budget, (rule, where, detail) => found.push({ rule, where, detail }));
	const counted = new RegExp(budget.countedFixtureFile);
	const table = new RegExp(budget.fixtureFile);
	// Fixtures count as test lines; other tables, such as vectors, still do not.
	const asTest = (p: Pkg, f: string) =>
		counted.test(f) || (budgetsAsTest(s, p, f) && !table.test(f));
	for (const p of packages) {
		const { cardDirs, unitOf, cardOf, whereOf } = unitsOf(p);
		for (const unit of ["", ...cardDirs]) {
			const where = whereOf(unit);
			const over = (what: string, value: number, limit: number, note = "") => {
				if (value > limit) s.report("measure", where, `${what} ${value} > ${limit}${note}`);
			};
			const card = cardOf(unit) ?? "";
			for (const line of card.split("\n").filter((l) => /^\s*- /.test(l))) {
				const opening = line.replace(/^\s*- /, "").slice(0, 12);
				over("card item bytes", Buffer.byteLength(line), budget.cardItemBytes, ` (${opening}…)`);
			}
			const tests = s.sources(p).filter((f) => unitOf(f) === unit && asTest(p, f));
			const lines = tests.reduce((sum, f) => sum + countLines(join(p.dir, f)).code, 0);
			over("test lines with fixtures", lines, budget.testLines);
		}
	}
	return found;
}
