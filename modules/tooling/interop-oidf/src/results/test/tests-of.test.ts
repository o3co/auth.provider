import { describe, expect, it } from "vitest";
import { testsOf } from "../results.ts";

describe("each test of a plan the suite ran, read back from its API", () => {
	const api = (answers: Record<string, unknown>) => async (path: string) => {
		if (!(path in answers)) throw new Error(`no answer to ${path}`);
		return answers[path];
	};

	it("reads each test's latest instance, its result and its log, and one that never ran with none", async () => {
		const tests = await testsOf(
			api({
				"api/plan?length=100": {
					data: [
						{ planName: "other", modules: [] },
						{
							planName: "oidcc-basic-certification-test-plan",
							modules: [
								{ testModule: "oidcc-server", variant: { a: "1" }, instances: ["i1", "i2"] },
								{ testModule: "oidcc-never", instances: [] },
							],
						},
					],
				},
				"api/info/i2": { status: "FINISHED", result: "PASSED" },
				"api/log/i2": [{ src: "Check", result: "SUCCESS" }],
			}),
			"oidcc-basic-certification-test-plan",
		);
		expect(tests).toEqual([
			{
				testModule: "oidcc-server",
				variant: { a: "1" },
				instance: "i2",
				info: { status: "FINISHED", result: "PASSED" },
				log: [{ src: "Check", result: "SUCCESS" }],
			},
			{ testModule: "oidcc-never", variant: {}, log: [] },
		]);
	});

	it("fails where the suite holds no such plan", async () => {
		await expect(testsOf(api({ "api/plan?length=100": { data: [] } }), "missing")).rejects.toThrow(
			"the suite holds no plan missing",
		);
	});

	const twoOfOneName = {
		"api/plan?length=100": {
			data: [
				{
					_id: "counted",
					planName: "oidcc-client-test-plan",
					modules: [{ testModule: "a", instances: ["c1"] }],
				},
				{
					_id: "uncounted",
					planName: "oidcc-client-test-plan",
					modules: [{ testModule: "a", instances: ["u1"] }],
				},
			],
		},
		"api/info/c1": { status: "FINISHED", result: "PASSED" },
		"api/log/c1": [],
		"api/info/u1": { status: "FINISHED", result: "FAILED" },
		"api/log/u1": [],
	};

	it("reads the plan its id names, never another of the same name", async () => {
		const tests = await testsOf(api(twoOfOneName), "oidcc-client-test-plan", "counted");
		expect(tests.map((t) => t.instance)).toEqual(["c1"]);
		await expect(testsOf(api(twoOfOneName), "another-plan", "counted")).rejects.toThrow(
			"the suite's plan counted is oidcc-client-test-plan, not another-plan",
		);
		await expect(testsOf(api(twoOfOneName), "oidcc-client-test-plan", "gone")).rejects.toThrow(
			"the suite holds no plan gone",
		);
	});

	it("refuses to choose by name between two plans of that name", async () => {
		await expect(testsOf(api(twoOfOneName), "oidcc-client-test-plan")).rejects.toThrow(
			"the suite holds 2 plans named oidcc-client-test-plan: name the one to read by its id",
		);
	});
});
