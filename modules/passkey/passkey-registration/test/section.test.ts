import { expect, it } from "vitest";
import { section } from "../src/section.ts";

it("counts 60 requests in 300 seconds unless the operator says otherwise", () => {
	expect(section.parse({})).toEqual({ requests: 60, "window-seconds": 300 });
});

it("takes 1 to 100000 requests in 1 to 86400 seconds, whole numbers only", () => {
	const accepts = (settings: object) => section.safeParse(settings).success;
	expect(accepts({ requests: 1, "window-seconds": 1 })).toBe(true);
	expect(accepts({ requests: 100_000, "window-seconds": 86_400 })).toBe(true);
	for (const settings of [
		{ requests: 0 },
		{ requests: 100_001 },
		{ requests: 1.5 },
		{ "window-seconds": 0 },
		{ "window-seconds": 86_401 },
		{ extra: 1 },
	]) {
		expect(accepts(settings), JSON.stringify(settings)).toBe(false);
	}
});
