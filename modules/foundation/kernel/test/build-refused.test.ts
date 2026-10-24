import { describe, expect, it } from "vitest";
import { BuildRefused } from "../src/contract.ts";
import { unreadable } from "./refusals.ts";

describe("BuildRefused.is", () => {
	it("tells a library's refusal by the mark every copy of the kernel puts on it, with where and why", () => {
		const refused = new BuildRefused(
			"records-test",
			"a space holds records or secret records, not both",
		);
		expect(BuildRefused.is(refused)).toBe(true);
		expect([refused.where, refused.reason]).toEqual([
			"records-test",
			"a space holds records or secret records, not both",
		]);
		// What a second copy of the kernel, bundled apart, throws: another class with the same mark.
		const elsewhere = Object.assign(new Error("x: y"), {
			[Symbol.for("@mod/kernel.build-refused")]: true,
			where: "x",
			reason: "y",
		});
		expect(BuildRefused.is(elsewhere)).toBe(true);
	});

	it("takes nothing else for one: a name alone, a mark of another value, or no object", () => {
		const named = Object.assign(new Error("x: y"), { name: "BuildRefused" });
		const other = { [Symbol.for("@mod/kernel.build-refused")]: "yes" };
		for (const value of [named, other, new Error("x"), "BuildRefused", null, undefined, 0]) {
			expect(BuildRefused.is(value), String(value)).toBe(false);
		}
	});

	it("takes nothing whose mark or fields cannot be read, or are not one line each, and never throws", () => {
		const mark = Symbol.for("@mod/kernel.build-refused");
		const throwing = (key: PropertyKey) =>
			Object.defineProperty({ [mark]: true, where: "w", reason: "r" }, key, {
				get() {
					throw new Error("token=abc");
				},
			});
		const looking = [
			{ [mark]: true },
			{ [mark]: true, where: 1, reason: "r" },
			{ [mark]: true, where: "w", reason: "line\nrefused invented: forged" },
			{ [mark]: true, where: "", reason: "r" },
			throwing(mark),
			throwing("where"),
			throwing("reason"),
			...unreadable(),
		];
		for (const value of looking) expect(BuildRefused.is(value)).toBe(false);
	});
});

describe("new BuildRefused", () => {
	it("refuses a where or reason that is not one public line within its length", () => {
		const rule =
			"a refusal's where and reason are one line each, 1 to 200 and 1 to 500 characters, with no control or format character";
		for (const [where, reason] of [
			["", "r"],
			["w", ""],
			["w", "token=abc\nrefused invented: forged"],
			["w\r", "r"],
			["w", "tab\there"],
			["w", "line\u2028separator"],
			["w", "bidi\u202eoverride"],
			["w".repeat(201), "r"],
			["w", "r".repeat(501)],
		] as const) {
			expect(() => new BuildRefused(where, reason), JSON.stringify([where, reason])).toThrow(rule);
		}
		expect(new BuildRefused("w".repeat(200), "r".repeat(500)).reason).toHaveLength(500);
	});
});
