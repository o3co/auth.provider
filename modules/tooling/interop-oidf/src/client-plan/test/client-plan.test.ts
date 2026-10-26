import { describe, expect, it } from "vitest";
import { declarationProblem, heldApps } from "../client-plan.ts";

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
		expect(declarationProblem(held, { run: ["a", "b"], notRun: ["c"], bootOnly: ["c"] })).toBe(
			"run otherwise, but not declared run: c",
		);
		expect(declarationProblem(["a", "new"], { run: ["a", "old"], notRun: [] })).toBe(
			"declared neither run nor not run: new; declared, but the plan holds none: old",
		);
	});
});

describe("the apps a relying party plan starts", () => {
	const app = (fails: number) => {
		let left = fails;
		const calls: string[] = [];
		return {
			calls,
			stop: async () => {
				calls.push("stop");
				if (left-- > 0) throw new Error("the app would not stop");
			},
		};
	};

	it("are held among the run's stops while they run, and let go once one stops", async () => {
		const stops: (() => Promise<unknown>)[] = [];
		const apps = heldApps(stops);
		const one = app(0);
		expect(
			await apps.run(one, async () => {
				expect(stops).toHaveLength(1);
				return "side";
			}),
		).toBe("side");
		expect([stops.length, apps.failed, one.calls]).toEqual([0, [], ["stop"]]);
	});

	it("keep one whose stop failed for the run's end, its failure told, whatever the use came to", async () => {
		const stops: (() => Promise<unknown>)[] = [];
		const apps = heldApps(stops);
		await expect(apps.run(app(1), async () => "side")).rejects.toThrow("the app would not stop");
		await expect(
			apps.run(app(1), async () => {
				throw new Error("the probe failed");
			}),
		).rejects.toThrow("the probe failed");
		expect(stops).toHaveLength(2);
		expect(apps.failed.map(String)).toEqual([
			"Error: the app would not stop",
			"Error: the app would not stop",
		]);
		// The run's end tries each again.
		for (const stop of stops) await stop();
	});
});
