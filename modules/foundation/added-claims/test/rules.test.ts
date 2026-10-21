import { describe, expect, it } from "vitest";
import { addedClaimsOf } from "../src/contract.ts";

// The limits are written as numbers here, not read from the rules, so changing one fails a test.
const refusedFor = (given: unknown): string => {
	try {
		addedClaimsOf(given);
	} catch (error) {
		if (error instanceof TypeError) return error.message;
		throw error;
	}
	return "taken";
};
const filled = (n: number, value: unknown = 0) => Array.from({ length: n }, () => value);
const membersOf = (n: number) => Object.fromEntries(filled(n).map((_, at) => [`m${at}`, 0]));

describe("the shape an added claim takes", () => {
	it("refuses an object's own names at any depth: __proto__, constructor, prototype and toJSON", () => {
		for (const name of ["__proto__", "constructor", "prototype", "toJSON"]) {
			const at = (depth: number) => {
				let value: unknown = JSON.parse(`{"${name}": "x"}`);
				for (let level = 1; level < depth; level++) value = { a: value };
				return value;
			};
			for (const depth of [1, 2, 3]) {
				expect(refusedFor(at(depth)), `${name} at ${depth}`).toMatch(/keeps for itself/);
			}
		}
	});

	it("refuses a hidden property, a length among them on an object, and a property with a setter alone", () => {
		const hidden = Object.defineProperty({ a: 1 }, "b", { value: 1, enumerable: false });
		expect(refusedFor({ a: hidden })).toMatch(/hidden property/);
		const length = Object.defineProperty({}, "length", { value: 1, enumerable: false });
		expect(refusedFor({ a: length })).toMatch(/hidden property/);
		expect(refusedFor({ a: [1, 2] })).toBe("taken");
		const setter = Object.defineProperty({}, "a", { set: () => {}, enumerable: true });
		expect(refusedFor({ a: setter })).toMatch(/accessor/);
	});

	it("takes 256 members to an object and refuses 257, at the top and nested", () => {
		expect(refusedFor(membersOf(256))).toBe("taken");
		expect(refusedFor(membersOf(257))).toMatch(/more than 256 claims/);
		// Each member nested is two values; 256 of them with their object stay within the 1024.
		expect(refusedFor({ a: membersOf(256) })).toBe("taken");
		expect(refusedFor({ a: membersOf(257) })).toMatch(/more than 256 members/);
	});

	it("takes 1024 values in all and refuses 1025", () => {
		// Five arrays: 5 values of their own, and 1019 or 1020 within them.
		const values = (inside: number) => ({
			a: filled(204),
			b: filled(204),
			c: filled(204),
			d: filled(204),
			e: filled(inside - 816),
		});
		expect(refusedFor(values(1019))).toBe("taken");
		expect(refusedFor(values(1020))).toMatch(/more than 1024 values/);
	});

	it("tells a cycle from depth: an object holding itself is refused as that", () => {
		const cycle: Record<string, unknown> = {};
		cycle.self = cycle;
		expect(refusedFor({ a: cycle })).toMatch(/holds itself/);
		const shared = { x: 1 };
		expect(refusedFor({ a: shared, b: shared })).toBe("taken");
	});
});

describe("the walk stops at the first limit it passes", () => {
	it("counts an object's members before reading any, so 300 accessors are refused for their number", () => {
		const accessors = {};
		for (let at = 0; at < 300; at++) {
			Object.defineProperty(accessors, `m${at}`, { get: () => 1, enumerable: true });
		}
		expect(refusedFor(accessors)).toMatch(/more than 256 claims/);
		expect(refusedFor({ a: accessors })).toMatch(/more than 256 members/);
		const wide = Object.assign(
			filled(2),
			Object.fromEntries(filled(300).map((_, at) => [`p${at}`, 1])),
		);
		expect(refusedFor({ a: wide })).toMatch(/property beside its values/);
	});

	it("measures a string and a name by its length first, never walking a long one to its end", () => {
		// Lone surrogates past twice the limit: refused for their length, before they are read.
		expect(refusedFor({ a: "\uD800".repeat(4097) })).toMatch(/over 2048 code points/);
		expect(refusedFor({ ["\uD800".repeat(511)]: 1 })).toMatch(/not 1 to 255 code points/);
		expect(refusedFor({ a: "x".repeat(2048) })).toBe("taken");
		// 2048 code points that are 2548 UTF-16 units: counted in code points, an astral character is one.
		const mixed = `${"😀".repeat(500)}${"x".repeat(1548)}`;
		expect(refusedFor({ a: mixed })).toBe("taken");
		expect(refusedFor({ a: `${mixed}x` })).toMatch(/over 2048 code points/);
		expect(refusedFor({ ["é".repeat(255)]: 1 })).toBe("taken");
		expect(refusedFor({ ["😀".repeat(256)]: 1 })).toMatch(/not 1 to 255 code points/);
	});

	it("checks the values and the bytes as each grows, before going on to the next", () => {
		// Past 1024 values, a function after them is never reached.
		const over = { a: filled(256), b: filled(256), c: filled(256), d: filled(256), f: () => 1 };
		expect(refusedFor(over)).toMatch(/more than 1024 values/);
		// A name past 4096 bytes is refused before its value, a function, is looked at.
		const named = { a: "x".repeat(2048), b: "x".repeat(2000), ["n".repeat(100)]: () => 1 };
		expect(refusedFor(named)).toMatch(/over 4096 bytes/);
	});
});
