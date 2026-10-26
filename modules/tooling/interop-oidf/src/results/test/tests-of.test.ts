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
});
