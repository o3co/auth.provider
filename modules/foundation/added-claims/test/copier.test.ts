import { describe, expect, it } from "vitest";
import { addedClaimsIn, addedClaimsOf } from "../src/contract.ts";

describe("the added claims' copier", () => {
	const refuses = (given: unknown) => expect(() => addedClaimsOf(given)).toThrow(TypeError);

	it("copies a plain set into a new frozen one, and takes none for none or an empty set", () => {
		const given = { a: { b: [true, null, 1.5, "x"] } };
		const copied = addedClaimsOf(given);
		expect(copied).toEqual(given);
		expect(copied).not.toBe(given);
		expect(Object.isFrozen(copied?.a)).toBe(true);
		expect(addedClaimsOf(undefined)).toBeUndefined();
		expect(addedClaimsOf({})).toBeUndefined();
		expect(addedClaimsOf(Object.assign(Object.create(null), { a: 1 }))).toEqual({ a: 1 });
	});

	it("refuses what is not JSON or not plain, calling nothing it was given", () => {
		let called = false;
		const getter = Object.defineProperty({}, "a", {
			enumerable: true,
			get: () => {
				called = true;
				return 1;
			},
		});
		refuses(getter);
		refuses({ a: getter });
		const trapped = new Proxy(
			{},
			{
				ownKeys: () => {
					called = true;
					return [];
				},
			},
		);
		refuses(trapped);
		refuses({ a: trapped });
		expect(called).toBe(false);
		const cycle: Record<string, unknown> = {};
		cycle.self = cycle;
		refuses({ a: cycle });
		refuses({ a: { toJSON: () => 1 } });
		refuses({ [Symbol("a")]: 1 });
		refuses({ a: Symbol("a") });
		refuses({ a: 1n });
		refuses({ a: undefined });
		refuses({ a: Number.NaN });
		refuses({ a: Number.POSITIVE_INFINITY });
		// biome-ignore lint/suspicious/noSparseArray: the hole is what is refused
		refuses({ a: [1, , 2] });
		refuses({ a: Object.assign([1], { extra: 2 }) });
		refuses({ a: new Date(0) });
		refuses({ a: new (class Point {})() });
		refuses([1]);
		refuses("a");
		expect(Object.prototype).not.toHaveProperty("polluted");
	});

	it("refuses a name the issuer writes, aud_added among them, and reads none back from a payload", () => {
		for (const name of ["iss", "aud", "cnf", "aud_added"]) refuses({ [name]: 1 });
		expect(addedClaimsIn({ aud: ["a", "b"], aud_added: 1, team: "x" })).toEqual({ team: "x" });
	});

	it("takes names of 1 to 255 code points, well formed, with no control character or space", () => {
		expect(addedClaimsOf({ ["é".repeat(255)]: 1 })).toBeDefined();
		refuses({ ["é".repeat(256)]: 1 });
		refuses({ "": 1 });
		for (const name of ["a b", "a\tb", "a\u0000", "a\uD800", "a b"]) refuses({ [name]: 1 });
	});

	it("stops at each limit: a string's code points, members, depth, values and bytes", () => {
		expect(addedClaimsOf({ a: "x".repeat(2048) })).toBeDefined();
		// Counted in code points: an astral character is one.
		expect(addedClaimsOf({ a: "😀".repeat(1000) })).toBeDefined();
		refuses({ a: "x".repeat(2049) });
		refuses({ a: "a\uDC00" });
		expect(addedClaimsOf({ a: Array(256).fill(0) })).toBeDefined();
		refuses({ a: Array(257).fill(0) });
		const nested = (depth: number): unknown => (depth === 1 ? 1 : [nested(depth - 1)]);
		expect(addedClaimsOf({ a: nested(8) })).toBeDefined();
		refuses({ a: nested(9) });
		refuses({
			a: Array(200).fill([0, 0, 0, 0, 0, 0]),
		});
		// {"a":"…","b":"…"} is 15 bytes beside its two strings.
		const bytes = (n: number) => ({
			a: "x".repeat(2048),
			b: "x".repeat(n - 2048 - 15),
		});
		expect(addedClaimsOf(bytes(4096))).toBeDefined();
		refuses(bytes(4097));
	});
});
