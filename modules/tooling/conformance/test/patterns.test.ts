import { describe, expect, it, vi } from "vitest";
import { areaResult, runPatterns, runsOf } from "../src/patterns/patterns.ts";

const summaries = [
	{ name: "simple-web", use: "", areas: ["keys", "ops"] },
	{ name: "a2a", use: "", areas: [] },
	{ name: "full", use: "", areas: ["keys"] },
];

describe("the runs over the patterns", () => {
	it("runs each pattern's areas, and full's twice: as it is and with every opt-in", () => {
		expect(runsOf(summaries, [])).toEqual([
			{ pattern: "simple-web", areas: ["keys", "ops"] },
			{ pattern: "a2a", areas: [] },
			{ pattern: "full", areas: ["keys"] },
			{ pattern: "full+opt-ins", areas: ["keys"] },
		]);
	});

	it("runs the one pattern named on the areas named", () => {
		expect(runsOf(summaries, ["full+opt-ins", "keys", "oauth"])).toEqual([
			{ pattern: "full+opt-ins", areas: ["keys", "oauth"] },
		]);
		expect(runsOf(summaries, ["a2a"])).toEqual([{ pattern: "a2a", areas: [] }]);
	});

	it("refuses a pattern not known, naming those that are", () => {
		expect(() => runsOf(summaries, ["nope"])).toThrow(
			"nope: no such pattern (simple-web, a2a, full, full+opt-ins)",
		);
	});
});

describe("an area's result", () => {
	const tests = "      Tests  3 passed | 2 skipped (5)";

	it("gives the tests line and counts the scenes left out by reason", () => {
		const left = ["lacks @mod/dpop", "pauses the Store", "lacks @mod/dpop"];
		expect(areaResult(`x\n${tests}\ny`, 0, left)).toEqual({
			failed: false,
			line: "Tests  3 passed | 2 skipped (5) | not-in-pattern 3",
			reasons: ["2 lacks @mod/dpop", "1 pauses the Store"],
		});
	});

	it("reads a tests line its runner coloured, as a CI's terminal colours it", () => {
		const esc = String.fromCharCode(27);
		const coloured = (text: string) => text.replaceAll("^[", esc);
		const passed = coloured(
			"^[[2m      Tests ^[[22m ^[[1m^[[32m10 passed^[[39m^[[22m^[[90m (10)^[[39m",
		);
		expect(areaResult(`x\n${passed}\ny`, 0, [])).toEqual({
			failed: false,
			line: "Tests  10 passed (10) | not-in-pattern 0",
			reasons: [],
		});
		const failing = coloured(
			"^[[2m      Tests ^[[22m ^[[1m^[[31m1 failed^[[39m^[[22m^[[2m | ^[[22m^[[1m^[[32m2 passed^[[39m",
		);
		expect(areaResult(failing, 1, []).failed).toBe(true);
	});

	it("fails on a failed test, a non-zero exit or no tests line", () => {
		expect(areaResult("      Tests  1 failed | 2 passed (3)", 1, []).failed).toBe(true);
		expect(areaResult(tests, 1, []).failed).toBe(true);
		expect(areaResult("No projects matched", 0, [])).toEqual({
			failed: true,
			line: "no tests line | not-in-pattern 0",
			reasons: [],
		});
	});
});

describe("the pattern runs", () => {
	const passed = { failed: false, line: "Tests  1 passed (1) | not-in-pattern 0", reasons: [] };

	it("fail on a pattern with no areas", () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => {});
		expect(runPatterns(["a2a"], summaries, () => passed)).toBe(false);
		expect(log).toHaveBeenCalledWith("a2a: no areas FAILED");
		expect(runPatterns(["simple-web"], summaries, () => passed)).toBe(true);
		log.mockRestore();
	});
});
