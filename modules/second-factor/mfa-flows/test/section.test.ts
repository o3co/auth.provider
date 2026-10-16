import { expect, it } from "vitest";
import { section } from "../src/section.ts";

it("takes the operator's numbers whole and within their bounds, defaulting those left out", () => {
	expect(section.parse({})).toEqual({
		"transaction-seconds": 600,
		"attempts-per-transaction": 5,
		requests: 60,
		"window-seconds": 300,
		lockout: {
			threshold: 5,
			"backoff-seconds": 900,
			"max-backoff-seconds": 86_400,
			budget: 10,
			"budget-window-seconds": 604_800,
			"hard-limit": 100,
			"memory-seconds": 86_400,
		},
	});
	const bounds = {
		"transaction-seconds": [60, 1800],
		"attempts-per-transaction": [2, 10],
		requests: [1, 100_000],
		"window-seconds": [1, 86_400],
	};
	for (const [name, [min = 0, max = 0]] of Object.entries(bounds)) {
		const taken = (value: number) => [name, value, section.safeParse({ [name]: value }).success];
		for (const value of [min, max]) expect(taken(value)).toEqual([name, value, true]);
		for (const value of [min - 1, max + 1, min + 0.5])
			expect(taken(value)).toEqual([name, value, false]);
	}
	expect(section.safeParse({ "transaction-second": 600 }).success).toBe(false);
});
