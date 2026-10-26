import { rmdirSync, statSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { clientPlans, evidenceRuns, planCommands, plans, recordsOf } from "../src/plans.ts";

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

	it("runs every plan where none is named, the relying party's on its own pattern's configuration", () => {
		const all = [...Object.keys(plans), ...Object.keys(clientPlans)];
		expect(planCommands([]).map((c) => c.run)).toEqual(all);
		expect(planCommands(["basic", "rp"]).map((c) => c.args.join(" "))).toEqual([
			"exec vitest run --config vitest.config.ts runs/basic.test.ts",
			"exec vitest run --config vitest.rp.config.ts runs/rp.test.ts",
		]);
	});

	it("refuses a plan it does not hold, naming the ones it does", () => {
		expect(() => planCommands(["basic", "nope"])).toThrow(/nope.*basic/);
	});

	it("declares each plan a gate run, whose failed tests stop a release whatever items they name", () => {
		expect(evidenceRuns).toEqual(
			[...Object.keys(plans), ...Object.keys(clientPlans)].map((name) => ({
				entry: `@mod/interop-oidf#${name}`,
				kind: "oidf-plan",
				matrix: name,
				gate: true,
			})),
		);
	});

	it("keeps the plans' records where they are named, and in a directory it makes and names otherwise", async () => {
		expect(await recordsOf("/records")).toEqual({ dir: "/records", made: false });
		// With none named, a killed run's suite still leaves its logs somewhere told.
		const made = await recordsOf(undefined);
		expect(made.made).toBe(true);
		expect(statSync(made.dir).isDirectory()).toBe(true);
		rmdirSync(made.dir);
	});
});
