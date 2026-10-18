import { expect, it } from "vitest";
import { section } from "../src/section.ts";

it("counts 60 requests a minute unless the operator says otherwise", () => {
	expect(section.parse({})).toEqual({ requests: 60, window: 60 });
});

it("takes 1 to 100000 requests in a window from 1s to 1d, written with its unit", () => {
	const accepts = (settings: object) => section.safeParse(settings).success;
	expect(accepts({ requests: 1, window: "1s" })).toBe(true);
	expect(accepts({ requests: 100_000, window: "1d" })).toBe(true);
	for (const settings of [
		{ requests: 0 },
		{ requests: 100_001 },
		{ window: "0s" },
		{ window: "86401s" },
		{ window: 60 },
		{ window: "60" },
		{ "window-seconds": 60 },
	]) {
		expect(accepts(settings), JSON.stringify(settings)).toBe(false);
	}
});
