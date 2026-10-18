import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

describe("code-grant's section", () => {
	it.each([
		["code-lifetime", "9s", "10s", "10m", "601s"],
		["sweep-interval", "0s", "1s", "1h", "3601s"],
	])("takes %s from its least to its most, and nothing outside", (key, under, low, high, over) => {
		const parses = (value: string) => section.safeParse({ [key]: value }).success;
		expect([under, low, high, over].map(parses)).toEqual([false, true, true, false]);
	});

	it("keeps a code 10 minutes and sweeps every 30 seconds where nothing is set", () => {
		expect(section.parse({})).toMatchObject({ "code-lifetime": 600, "sweep-interval": 30 });
	});

	it.each(["code-lifetime", "sweep-interval"])("refuses %s written with no unit", (key) => {
		expect(section.safeParse({ [key]: 30 }).success).toBe(false);
		expect(section.safeParse({ [key]: "30" }).success).toBe(false);
	});

	it("still takes the keys in seconds, in their bounds, while their writers move", () => {
		expect(section.parse({ "code-seconds": 60, "sweep-seconds": 1 })).toMatchObject({
			"code-seconds": 60,
			"sweep-seconds": 1,
		});
		expect(section.safeParse({ "code-seconds": 601 }).success).toBe(false);
		expect(section.safeParse({ "sweep-seconds": 0 }).success).toBe(false);
	});
});
