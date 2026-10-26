import { describe, expect, it } from "vitest";
import type { PlanRun } from "./report.ts";

/** A suite test's title: its name and its variant, as the suite shows them. */
const titleOf = (testModule: string, variant: Readonly<Record<string, string>>) => {
	const shown = Object.entries(variant).map(([key, value]) => `${key}=${value}`);
	return shown.length === 0 ? testModule : `${testModule} [${shown.join("][")}]`;
};

/**
 * Reports a plan's run as vitest tests under `title`: one per suite test, passed, failed with why, or
 * skipped with the class that excused it or as waiting for a person's review; then the expected
 * entries no test used, and the driver's own word.
 */
export function reportRun(title: string, run: PlanRun): void {
	describe(title, () => {
		for (const m of run.modules) {
			it(titleOf(m.testModule, m.variant), (context) => {
				const o = m.outcome;
				if (o.kind === "excused") return context.skip(`excused: ${o.class}`);
				if (o.kind === "review")
					return context.skip("review: the suite asks a person to review the result");
				expect(o.kind === "failed" ? o.why : [], `see ${run.artifacts}`).toEqual([]);
			});
		}
		it("uses every expected entry", () => {
			expect(run.unused.map((e) => `${e["test-name"]} ${e.condition ?? "(skip)"}`)).toEqual([]);
		});
		it(`is passed by ${run.driver.name}`, () => {
			expect(run.driver.code, `see ${run.artifacts}/${run.driver.log}`).toBe(0);
		});
	});
}
