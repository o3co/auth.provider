import { describe, expect, it } from "vitest";
import { skippedFaultScenes } from "../src/fault-run.ts";

const module = (file: string, tests: [string, string][]) => ({
	moduleId: file,
	children: { allTests: () => tests.map(([name, state]) => ({ name, result: () => ({ state }) })) },
});

describe("a fault run", () => {
	it("names every fault scene that did not run, and none of another file", () => {
		const modules = [
			module("/x/code.faults.case.ts", [
				["takes a code once {fault:Lr}", "passed"],
				["takes a code once {fault:F}", "skipped"],
			]),
			module("/x/code.case.ts", [["other", "skipped"]]),
		];
		expect(skippedFaultScenes(modules)).toEqual([
			"/x/code.faults.case.ts > takes a code once {fault:F}",
		]);
	});
});
