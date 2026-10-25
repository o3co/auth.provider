import { describe, expect, it, vi } from "vitest";
import {
	areaResult,
	evidenceRuns,
	failureOf,
	patternNames,
	runPatterns,
	runsOf,
} from "../src/patterns/patterns.ts";

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

	it("names every run's pattern, full+opt-ins included, for a job to run each on its own", () => {
		expect(patternNames(summaries)).toEqual(["simple-web", "a2a", "full", "full+opt-ins"]);
	});

	it("lists every run of an area's scenes on a pattern's app, as the evidence of a CI run counts it", () => {
		const run = (entry: string, matrix: string) => ({ entry, kind: "pattern", matrix });
		expect(evidenceRuns(summaries)).toEqual([
			run("@mod/conformance-keys@simple-web", "simple-web"),
			run("@mod/conformance-ops@simple-web", "simple-web"),
			run("@mod/conformance@a2a", "a2a"),
			run("@mod/conformance-keys@full", "full"),
			run("@mod/conformance-keys@full+opt-ins", "full+opt-ins"),
		]);
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
			told: "No projects matched",
		});
	});
});

describe("what a failed area tells", () => {
	const suiteFailed = [
		"progress line",
		...Array.from({ length: 50 }, (_, i) => `noise ${i}`),
		"⎯⎯⎯⎯⎯⎯ Failed Suites 1 ⎯⎯⎯⎯⎯⎯⎯",
		" FAIL  test/mfa.case.ts > second factor",
		"Error: refused:",
		"redis: the store cannot be reached",
		"      Tests  4 skipped (4)",
	].join("\n");

	it("is its failures as vitest tells them, from their heading on", () => {
		expect(failureOf(suiteFailed)).toBe(
			[
				"⎯⎯⎯⎯⎯⎯ Failed Suites 1 ⎯⎯⎯⎯⎯⎯⎯",
				" FAIL  test/mfa.case.ts > second factor",
				"Error: refused:",
				"redis: the store cannot be reached",
				"      Tests  4 skipped (4)",
			].join("\n"),
		);
	});

	it("is its last lines where nothing heads its failures", () => {
		const lines = Array.from({ length: 100 }, (_, i) => `line ${i}`);
		const told = failureOf(lines.join("\n")).split("\n");
		expect(told).toHaveLength(60);
		expect(told.at(-1)).toBe("line 99");
	});

	it("goes with an area that failed, a skipped scene's refusal included where no test failed", () => {
		const failed = areaResult(suiteFailed, 1, []);
		expect(failed.failed).toBe(true);
		expect(failed.told).toContain("redis: the store cannot be reached");
		expect(areaResult("      Tests  1 passed (1)", 0, []).told).toBeUndefined();
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

	it("print what a failed area told, and where its whole output is kept", () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => {});
		const failed = {
			failed: true,
			line: "Tests  4 skipped (4) | not-in-pattern 0",
			reasons: [],
			told: "Error: refused:",
			kept: "/tmp/x/output.log",
		};
		expect(runPatterns(["simple-web"], summaries, () => failed)).toBe(false);
		const printed = log.mock.calls.map((call) => String(call[0])).join("\n");
		expect(printed).toContain("FAILED");
		expect(printed).toContain("  Error: refused:");
		expect(printed).toContain("/tmp/x/output.log");
		log.mockRestore();
	});
});
