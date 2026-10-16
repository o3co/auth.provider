import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

describe("federation-tokens' section", () => {
	it.each([
		["refresh-before-seconds", 0, 3600],
		["max-lifetime-seconds", 60, 31_536_000],
		["lock-seconds", 1, 60],
		["requests", 1, 1000],
		["window-seconds", 1, 3600],
	])("takes %s in whole numbers from %i to %i, and nothing outside", (key, low, high) => {
		const parses = (value: number) => section.safeParse({ [key]: value }).success;
		expect([
			parses(low - 1),
			parses(low),
			parses(low + 0.5),
			parses(high),
			parses(high + 1),
		]).toEqual([false, true, false, true, false]);
	});

	it("defaults each setting, and refuses one it does not know", () => {
		expect(section.parse({})).toEqual({
			"refresh-before-seconds": 30,
			"max-lifetime-seconds": 86_400,
			"lock-seconds": 5,
			requests: 60,
			"window-seconds": 60,
		});
		expect(section.safeParse({ "lock-second": 5 }).success).toBe(false);
	});
});
