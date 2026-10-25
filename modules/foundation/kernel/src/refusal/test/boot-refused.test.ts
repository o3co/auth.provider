import { describe, expect, it } from "vitest";
import { unreadable } from "../../../test/refusals.ts";
import { BootRefused } from "../../contract.ts";

describe("BootRefused.is", () => {
	it("tells a refused boot by the mark every copy of the kernel puts on it, never by its class", () => {
		expect(BootRefused.is(new BootRefused([{ where: "kernel", reason: "no" }]))).toBe(true);
		// What a second copy of the kernel, bundled apart, throws: another class with the same mark.
		const elsewhere = Object.assign(new Error("boot refused (1)"), {
			[Symbol.for("@mod/kernel.boot-refused")]: true,
			refusals: [{ where: "kernel", reason: "no" }],
		});
		expect(BootRefused.is(elsewhere)).toBe(true);
	});

	it("answers false, never throwing, for a value whose mark cannot be read", () => {
		for (const value of unreadable()) expect(BootRefused.is(value)).toBe(false);
	});

	it("takes nothing else for a refused boot: a name alone, a mark of another value, or no object", () => {
		const named = Object.assign(new Error("boot refused (1)"), { name: "BootRefused" });
		const other = { [Symbol.for("@mod/kernel.boot-refused")]: "yes" };
		for (const value of [named, other, new Error("x"), "BootRefused", null, undefined, 0]) {
			expect(BootRefused.is(value), String(value)).toBe(false);
		}
	});
});
