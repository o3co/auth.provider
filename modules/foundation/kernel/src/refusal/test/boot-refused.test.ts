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

describe("a BootRefused's refusals", () => {
	it("are read one at a time into its own frozen list, a hole or a value of another shape left out, never throwing", () => {
		const secret = {
			where: "w",
			get reason(): string {
				throw new Error("secret=abc");
			},
		};
		// biome-ignore lint/suspicious/noSparseArray: a list with a hole is the case.
		const given = [, { where: "kernel", reason: "no" }, secret, { where: 1, reason: "r" }, null];
		const refused = new BootRefused(given as never);
		expect(refused.refusals).toEqual([{ where: "kernel", reason: "no" }]);
		expect(Object.isFrozen(refused.refusals) && Object.isFrozen(refused.refusals[0])).toBe(true);
		expect(refused.message).toBe("boot refused (1)");
	});
});
