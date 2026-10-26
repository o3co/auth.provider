import { describe, expect, it } from "vitest";
import { declarationProblem } from "../client-plan.ts";

describe("a relying party plan's declared tests", () => {
	it("hold where every test of the suite's plan is run or not run, never both, and none is declared besides", () => {
		const held = ["a", "b", "c"];
		expect(declarationProblem(held, { run: ["a", "b"], notRun: ["c"] })).toBeUndefined();
		expect(declarationProblem(held, { run: ["a", "c"], notRun: ["c", "b"] })).toBe(
			"declared both run and not run: c",
		);
		expect(declarationProblem(held, { run: ["a"], notRun: ["b"] })).toBe(
			"declared neither run nor not run: c",
		);
		expect(declarationProblem(held, { run: ["a", "b", "c"], notRun: ["gone"] })).toBe(
			"declared, but the plan holds none: gone",
		);
		expect(declarationProblem(["a", "new"], { run: ["a", "old"], notRun: [] })).toBe(
			"declared neither run nor not run: new; declared, but the plan holds none: old",
		);
	});
});
