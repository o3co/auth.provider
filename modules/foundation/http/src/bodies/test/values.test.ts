import { expect, it } from "vitest";
import { fieldsOf, paramsOf, valuesOf } from "../values.ts";

it("answers a name's value only when it holds exactly one", () => {
	const values = paramsOf(new URLSearchParams("a=1&b=2&b=3&c="));
	expect([values.single("a"), values.single("b"), values.single("c"), values.single("d")]).toEqual([
		"1",
		undefined,
		"",
		undefined,
	]);
	expect(valuesOf(new Map([["e", []]])).single("e")).toBeUndefined();
});

it("lists the names holding more than one value, in the order sent", () => {
	expect(paramsOf(new URLSearchParams("z=1&a=2&z=3&m=4&a=5")).repeated()).toEqual(["z", "a"]);
	expect(paramsOf(new URLSearchParams("a=1&b=2")).repeated()).toEqual([]);
	expect(fieldsOf({ a: "1", b: "2", n: 3 }).fields.repeated()).toEqual([]);
});

it("throws on writes, and keeps its value lists frozen", () => {
	const values = valuesOf(new Map([["a", ["1"]]]));
	const map = values as unknown as Map<string, string[]>;
	expect(() => map.set("a", [])).toThrow(TypeError);
	expect(() => map.delete("a")).toThrow(TypeError);
	expect(() => map.clear()).toThrow(TypeError);
	expect(Object.isFrozen(values.get("a"))).toBe(true);
	expect(Object.isFrozen(values.repeated())).toBe(true);
});
