import { expect, it } from "vitest";
import { fieldsOf, readOnly, valuesOf } from "../values.ts";

it("answers a name's value only when it holds exactly one", () => {
	const values = valuesOf(
		new Map([
			["a", ["1"]],
			["b", ["2", "3"]],
			["c", [""]],
			["e", []],
		]),
	);
	expect([..."abcde"].map((name) => values.single(name))).toEqual([
		"1",
		undefined,
		"",
		undefined,
		undefined,
	]);
});

it("lists the names holding more than one value, in the order given", () => {
	const values = valuesOf(
		new Map([
			["z", ["1", "3"]],
			["a", ["2", "5"]],
			["m", ["4"]],
		]),
	);
	expect(values.repeated()).toEqual(["z", "a"]);
	expect(valuesOf(new Map([["a", ["1"]]])).repeated()).toEqual([]);
});

it("throws on writes, and keeps its value lists frozen", () => {
	const values = valuesOf(new Map([["a", ["1"]]]));
	const map = values as unknown as Map<string, string[]>;
	expect(() => map.set("a", [])).toThrow(TypeError);
	expect(() => map.delete("a")).toThrow(TypeError);
	expect(() => map.clear()).toThrow(TypeError);
	expect(Object.isFrozen(values.get("a"))).toBe(true);
	expect(Object.isFrozen(values.repeated())).toBe(true);
	const plain = readOnly(new Map([["a", "1"]])) as Map<string, string>;
	expect(() => plain.set("a", "2")).toThrow(TypeError);
	expect(plain.get("a")).toBe("1");
});

it("gives a JSON object's strings as fields and its other members as mistyped, neither writable", () => {
	const read = fieldsOf({ a: "1", b: "2", n: 3, o: { x: "y" } });
	expect(Object.fromEntries(read.fields)).toEqual({ a: ["1"], b: ["2"] });
	expect(read.fields.repeated()).toEqual([]);
	expect([...(read.mistyped ?? [])]).toEqual(["n", "o"]);
	expect(() => (read.mistyped as Set<string>).add("p")).toThrow(TypeError);
	expect(fieldsOf({ a: "1" })).not.toHaveProperty("mistyped");
});
