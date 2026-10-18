import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

const parses = (settings: Record<string, unknown>) => section.safeParse(settings).success;

describe("federation-tokens' section", () => {
	it.each([
		["refresh-before", 0, 3600],
		["max-lifetime", 60, 31_536_000],
		["lock-lifetime", 1, 60],
		["window", 1, 3600],
	])(
		"takes %s from %is to %is, whole seconds written with their unit, and nothing outside",
		(key, low, high) => {
			const takes = (value: unknown) => parses({ [key]: value });
			const seconds = [low - 1, low, low + 0.5, high, high + 1].map((n) => `${n}s`);
			expect(seconds.map(takes)).toEqual([false, true, false, true, false]);
			expect([high, String(high)].map(takes)).toEqual([false, false]);
		},
	);

	it("takes requests in whole numbers from 1 to 1000, and nothing outside", () => {
		const takes = (value: number) => parses({ requests: value });
		expect([0, 1, 1.5, 1000, 1001].map(takes)).toEqual([false, true, false, true, false]);
	});

	it("defaults each setting, read as an operator's value is, and refuses one it does not know", () => {
		expect(section.parse({})).toEqual({
			"refresh-before": 30,
			"max-lifetime": 86_400,
			"lock-lifetime": 5,
			requests: 60,
			window: 60,
		});
		expect(parses({ "lock-second": "5s" })).toBe(false);
	});
});
