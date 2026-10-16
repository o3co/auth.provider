import { describe, expect, it } from "vitest";
import { deepFreeze } from "../src/contract.ts";

describe("deepFreeze", () => {
	it("freezes the children of a parent that is already frozen", () => {
		const child = { name: "inner" };
		const value = deepFreeze(Object.freeze({ child }));
		expect(Object.isFrozen(value.child)).toBe(true);
	});

	it("freezes what a symbol key holds", () => {
		const key = Symbol("inner");
		const value = deepFreeze({ [key]: { name: "inner" } });
		expect(Object.isFrozen(value[key])).toBe(true);
	});

	it("freezes a value that holds itself", () => {
		const value: { self?: unknown; list: number[] } = { list: [1] };
		value.self = value;
		deepFreeze(value);
		expect(Object.isFrozen(value)).toBe(true);
		expect(Object.isFrozen(value.list)).toBe(true);
	});
});
