import { describe, expect, it } from "vitest";
import { testRequest } from "../src/testing.ts";

describe("test requests", () => {
	it("give fields from their JSON or form, as the server does", () => {
		const form = new Map([["a", ["1", "2"]]]);
		expect([...testRequest({ form }).fields]).toEqual([...form]);
		expect(testRequest({ form }).fields.repeated()).toEqual(["a"]);
		expect(testRequest({ query: new Map([["q", ["1"]]]) }).query.single("q")).toBe("1");
		expect([...testRequest({ json: { a: "1", n: 2 } }).fields]).toEqual([["a", ["1"]]]);
		expect([...(testRequest({ json: { a: "1", n: 2 } }).mistyped ?? [])]).toEqual(["n"]);
		expect(testRequest({ form }).mistyped).toBeUndefined();
		const mistyped = testRequest({ json: { n: 2 } }).mistyped as Set<string>;
		expect(() => mistyped.add("x")).toThrow(TypeError);
		expect(() => mistyped.delete("n")).toThrow(TypeError);
		expect(() => mistyped.clear()).toThrow(TypeError);
		expect(testRequest().fields.size).toBe(0);
	});

	it("are read-only as the server's are", () => {
		const json = { a: "1", nested: { b: [2] } };
		const sent = new Map([["x", "1"]]);
		const request = testRequest({ json, headers: sent });
		expect(() => (request.headers as Map<string, string>).set("y", "2")).toThrow(TypeError);
		expect(sent.set("y", "2").get("y")).toBe("2");
		expect(Object.isFrozen(request.json?.nested)).toBe(true);
		expect(Object.isFrozen(json)).toBe(false);
		expect(Object.isFrozen(request.source)).toBe(true);
		expect(Object.isFrozen(request)).toBe(true);
	});
});
