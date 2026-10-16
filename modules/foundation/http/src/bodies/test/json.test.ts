import { expect, it } from "vitest";
import { repeatsName } from "../json.ts";

it("finds a member name given twice in one object, at any depth, however it is escaped", () => {
	for (const text of [
		'{"a":"1","a":"2"}',
		'{"x":{"b":1,"c":[],"b":2}}',
		'{"l":[1,{"a":1,"a":1}]}',
		'{"a":"1","\\u0061":"2"}',
		'{ "a" : 1 , "a" : 2 }',
		'{"a\\"b":1,"a\\"b":2}',
		'{"x":"{","a":1,"a":2}',
		'{"a":1,"x":"}","a":2}',
	]) {
		expect(repeatsName(text), text).toBe(true);
	}
});

it("tells names in other objects, and strings that are values, from repeated names", () => {
	for (const text of [
		'{"a":"1","b":"2"}',
		'{"a":{"a":1},"l":[{"a":1},{"a":2}]}',
		'{"a":"\\"a\\":","b":"{\\"a\\":1}","c":["a","a"]}',
		'{"a\\\\":1,"a":2}',
		'{"a":"a","l":["a","a","a"]}',
		'{"a":"{\\"b\\":1,\\"b\\":2}"}',
		"{}",
	]) {
		expect(repeatsName(text), text).toBe(false);
	}
});

it("ends, rather than looping, on a text cut inside a string", () => {
	expect(() => repeatsName('{"a')).toThrow(SyntaxError);
	expect(repeatsName('["a')).toBe(false);
});
