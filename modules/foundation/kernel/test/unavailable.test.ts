import { describe, expect, it } from "vitest";
import { isUnavailable, Unavailable } from "../src/contract.ts";

describe("isUnavailable", () => {
	it("tells an outage by the mark every copy of the kernel puts on it, never by its class", () => {
		expect(isUnavailable(new Unavailable("store"))).toBe(true);
		class Narrower extends Unavailable {}
		expect(isUnavailable(new Narrower("store"))).toBe(true);
		// What a second copy of the kernel, bundled apart, throws: another class with the same mark.
		const elsewhere = Object.assign(new Error("store unavailable"), {
			[Symbol.for("@mod/kernel.unavailable")]: true,
			what: "store",
		});
		expect(isUnavailable(elsewhere)).toBe(true);
	});

	it("takes nothing else for an outage: a name alone, a mark of another value, or no object", () => {
		const named = Object.assign(new Error("store unavailable"), { name: "Unavailable" });
		const other = { [Symbol.for("@mod/kernel.unavailable")]: "yes" };
		for (const value of [named, other, new Error("x"), "Unavailable", null, undefined, 0]) {
			expect(isUnavailable(value), String(value)).toBe(false);
		}
	});
});
