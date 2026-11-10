import { expect, it } from "vitest";
import { fieldsOf, paramsOf, type Values, valuesOf } from "../values.ts";

it("answers a name's value only when it holds exactly one", () => {
	const values = paramsOf("a=1&b=2&b=3&c=") as Values;
	expect([values.single("a"), values.single("b"), values.single("c"), values.single("d")]).toEqual([
		"1",
		undefined,
		"",
		undefined,
	]);
	expect(valuesOf(new Map([["e", []]])).single("e")).toBeUndefined();
});

/** The values a query's or a form's text reads as, by name; undefined when refused. */
const named = (text: string) => {
	const values = paramsOf(text);
	return values && Object.fromEntries(values);
};

it("reads percent-escapes as UTF-8 and `+` as a space, as form encoding does", () => {
	const valid = [
		"a=%C3%A9&b=x+y&c=&d=%E2%82%AC%F0%9F%98%80&%C3%A9=1&e=%c3%a9",
		"a=%25&b=%zz&c=%&d=%4&e=%%41&f=100%",
		"&&a&=x&b==c&a=%EF%BB%BFz&g=%2B+%20",
		"a=caf\u00e9&b=\u20ac",
	];
	for (const text of valid) {
		const pairs: [string, string][] = [...new URLSearchParams(text)];
		const grouped = [...Map.groupBy(pairs, ([name]) => name)];
		const before = Object.fromEntries(grouped.map(([name, all]) => [name, all.map(([, v]) => v)]));
		expect(named(text), text).toEqual(before);
	}
	expect(named("a=%C3%A9&b=x+y&c=")).toEqual({ a: ["é"], b: ["x y"], c: [""] });
});

it("refuses percent-escapes that are not well-formed UTF-8, in a name or a value", () => {
	for (const broken of [
		"a=%C3%28",
		"a=%E9",
		"%E9=1",
		"a=1&b=%ED%A0%80",
		"a=%C0%AF",
		"a=%F0%9F%98",
	]) {
		expect(paramsOf(broken), broken).toBeUndefined();
	}
});

it("lists the names holding more than one value, in the order sent", () => {
	expect(paramsOf("z=1&a=2&z=3&m=4&a=5")?.repeated()).toEqual(["z", "a"]);
	expect(paramsOf("a=1&b=2")?.repeated()).toEqual([]);
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
