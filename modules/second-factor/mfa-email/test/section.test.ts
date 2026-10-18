import { expect, it } from "vitest";
import { section } from "../src/section.ts";

it("lets a code live from 1m to 30m, written with its unit", () => {
	const takes = (value: unknown) => section.safeParse({ "code-lifetime": value }).success;
	expect(["59s", "1m", "30m", "1801s", 600, "600"].map(takes)).toEqual([
		false,
		true,
		true,
		false,
		false,
		false,
	]);
	expect(section.safeParse({ "code-seconds": 600 }).success).toBe(false);
});

it("is a factor of its own amr whose code lives 10m, where nothing is set", () => {
	expect(section.parse({})).toEqual({ "adds-second-factor": false, "code-lifetime": 600 });
});
