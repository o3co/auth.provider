import { describe, expect, it } from "vitest";
import { planCommands, plans } from "../src/plans.ts";

describe("the plans the package runs, one evidence run each", () => {
	it("starts one vitest for each plan named, on that plan's file, naming its run", () => {
		const commands = planCommands(["basic", "config"]);
		expect(commands).toEqual([
			{
				args: ["exec", "vitest", "run", "--config", "vitest.config.ts", "runs/basic.test.ts"],
				run: "basic",
			},
			{
				args: ["exec", "vitest", "run", "--config", "vitest.config.ts", "runs/config.test.ts"],
				run: "config",
			},
		]);
	});

	it("runs every plan where none is named", () => {
		expect(planCommands([]).map((c) => c.run)).toEqual(Object.keys(plans));
	});

	it("refuses a plan it does not hold, naming the ones it does", () => {
		expect(() => planCommands(["basic", "nope"])).toThrow(/nope.*basic/);
	});
});
