import { Unavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { list, numbers } from "../answer.ts";

it("reads a script's numbers, written as strings or as numbers, and leaves an absent or null one so", () => {
	expect(numbers({ kind: "counted", count: 2, resetAt: "1700000000000" })).toEqual({
		kind: "counted",
		count: 2,
		resetAt: 1700000000000,
	});
	expect(numbers({ kind: "exists", remainingMs: null })).toEqual({
		kind: "exists",
		remainingMs: null,
	});
});

it("answers unavailable where a number is no whole number, never reading it as one", () => {
	for (const resetAt of ["nan", "1.5", "", "1e3", 1.5, "99999999999999999999", true]) {
		expect(() => numbers({ kind: "limited", resetAt }), String(resetAt)).toThrow(Unavailable);
	}
});

it("rebuilds a list cjson wrote as an object, by its count", () => {
	expect(list<string>({ 0: "a", 2: "c" }, 3)).toEqual(["a", undefined, "c"]);
});
