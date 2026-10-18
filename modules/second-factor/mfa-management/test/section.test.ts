import { expect, it } from "vitest";
import { section } from "../src/section.ts";

const parses = (settings: object) => section.safeParse(settings).success;

it("counts 60 requests in 5 minutes unless the operator says otherwise, and refuses a setting it does not know", () => {
	expect(section.parse({})).toEqual({ requests: 60, window: 300 });
	expect(parses({ request: 60 })).toBe(false);
});

it("reads the window written with its unit, in whole seconds, never a bare number", () => {
	expect(section.parse({ window: "20m" }).window).toBe(1200);
	expect([600, "600", "1500ms"].map((window) => parses({ window }))).toEqual([false, false, false]);
	expect(parses({ "window-seconds": 300 })).toBe(false);
});

it("takes the window from 1s to 1d, and the requests whole from 1 to 100000", () => {
	expect(["0s", "1s", "86400s", "86401s"].map((window) => parses({ window }))).toEqual([
		false,
		true,
		true,
		false,
	]);
	const requests = [0, 1, 1.5, 100_000, 100_001].map((n) => parses({ requests: n }));
	expect(requests).toEqual([false, true, false, true, false]);
});
