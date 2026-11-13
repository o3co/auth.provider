import { describe, expect, it } from "vitest";
import { addedClaimsLimits, addedClaimsWith } from "../src/contract.ts";

describe("the limits an operator may raise", () => {
	it("read today's values where unset, and take each from them to its ceiling, never below", () => {
		expect(addedClaimsLimits.parse(undefined)).toEqual({
			"name-length": 255,
			"string-length": 2048,
			members: 256,
			values: 1024,
			depth: 8,
			size: 4096,
		});
		const takes = (limits: unknown) => addedClaimsLimits.safeParse(limits).success;
		for (const [key, floor, ceiling] of [
			["name-length", 255, 1024],
			["string-length", 2048, 8192],
			["members", 256, 1024],
			["values", 1024, 4096],
			["depth", 8, 16],
		] as const) {
			expect(
				[floor - 1, floor, ceiling, ceiling + 1].map((n) => takes({ [key]: n })),
				key,
			).toEqual([false, true, true, false]);
		}
		expect(["4095B", "4KiB", "8KiB", "8193B", 4096].map((size) => takes({ size }))).toEqual([
			false,
			true,
			true,
			false,
			false,
		]);
	});

	it("hold a grant's set and a token's read back to the limits given, alike", () => {
		const raised = addedClaimsWith(
			addedClaimsLimits.parse({ "string-length": 3000, members: 300, size: "8KiB" }),
		);
		const byDefault = addedClaimsWith(addedClaimsLimits.parse({}));
		const set = {
			x_list: Array.from({ length: 300 }, (_, n) => `e${n}`),
			x_text: "n".repeat(3000),
		};
		expect(raised.of(set)).toEqual(set);
		expect(raised.readBack(set)).toEqual(set);
		expect(() => byDefault.of(set)).toThrow(TypeError);
		expect(() => byDefault.readBack(set)).toThrow(TypeError);
	});
});
