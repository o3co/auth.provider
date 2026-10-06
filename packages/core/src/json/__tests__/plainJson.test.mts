/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { describe, expect, it } from "vitest";
import { copyPlainJson, copyPlainJsonNegativeZeroAsZero } from "../plainJson.mjs";

/** A value nested `depth` objects deep. */
const nested = (depth: number): unknown => {
	let value: unknown = {};
	for (let index = 0; index < depth; index++) value = { d: value };
	return value;
};

const listWithField = Object.assign([1], { foo: 1 });
const holed: unknown[] = [1];
holed[2] = 2;
const hidden = Object.defineProperty({}, "x", { value: 1, enumerable: false });
const hiddenToJSON = Object.defineProperty({}, "toJSON", { value: () => 1, enumerable: false });
const cycle: Record<string, unknown> = { a: 1 };
cycle.self = cycle;
const throwingEntry = Object.defineProperty([] as unknown[], 0, {
	get: () => {
		throw new Error("unreadable");
	},
	enumerable: true,
});
const revoked = Proxy.revocable({}, {});
revoked.revoke();

/** Values JSON gives back as they are, taken as they are. */
const TAKEN: readonly (readonly [string, unknown])[] = [
	["a plain object", { a: 1 }],
	["a null-prototype object", Object.assign(Object.create(null), { a: 1 })],
	[
		"an own getter, read once",
		{
			get a() {
				return 1;
			},
		},
	],
	[
		"an own getter answering undefined, left out",
		{
			get a() {
				return undefined;
			},
		},
	],
	["a field read as undefined, left out", { a: undefined }],
	["a list of lists", { a: [[1], [2]] }],
	["a list", [1]],
	["a string", "x"],
	["a number", 1],
	["null", null],
	[
		"an object two fields share",
		(() => {
			const s = { x: 1 };
			return { a: s, b: s };
		})(),
	],
	["an own __proto__ field", JSON.parse('{"__proto__": 1}')],
	["a Proxy over a plain object", new Proxy({ a: 1 }, {})],
	["a null-prototype object in a list", { a: [Object.create(null)] }],
];

/** Values JSON does not give back as they are, and where each is refused (`undefined`: wherever the stack ran out). */
const REFUSED: readonly (readonly [string, unknown, string | undefined])[] = [
	[
		"an own getter that throws",
		{
			get a() {
				throw new Error("unreadable");
			},
		},
		".a",
	],
	["-0", { a: -0 }, ".a"],
	["-0 in a list", { a: [1, -0] }, ".a[1]"],
	["a symbol's field", { [Symbol("s")]: 1, a: 1 }, ""],
	["a hidden field", hidden, ""],
	["a hidden toJSON", hiddenToJSON, ""],
	["a toJSON function", { toJSON: () => 1 }, ".toJSON"],
	["a list with a field beside its indices", { a: listWithField }, ".a"],
	["a hole", { a: holed }, ".a"],
	["undefined in a list", { a: [undefined] }, ".a[0]"],
	["a Date", { a: new Date(0) }, ".a"],
	["undefined", undefined, ""],
	["a cycle", cycle, ".self"],
	["NaN", { a: Number.NaN }, ".a"],
	["an infinity", { a: Number.POSITIVE_INFINITY }, ".a"],
	["a bigint", { a: 1n }, ".a"],
	["a Proxy over a Date", { a: new Proxy(new Date(0), {}) }, ".a"],
	["an Array subclass", { a: new (class extends Array {})() }, ".a"],
	["a boxed number", { a: new Number(1) }, ".a"],
	["a Map", { a: new Map() }, ".a"],
	["a class's instance", { a: new (class {})() }, ".a"],
	["a function", () => 1, ""],
	["a revoked Proxy", { a: revoked.proxy }, ".a"],
	["a list entry whose getter throws", { a: throwingEntry }, ".a[0]"],
	["nesting past the stack", nested(200_000), undefined],
];

describe("copyPlainJson", () => {
	it.each(TAKEN)("takes %s, as JSON gives it back", (_label, value) => {
		const taken = copyPlainJson(value);
		expect(taken.ok).toBe(true);
		if (!taken.ok) return;
		expect(JSON.parse(JSON.stringify(taken.copy))).toEqual(JSON.parse(JSON.stringify(value)));
	});

	it.each(REFUSED)("refuses %s, naming where", (_label, value, at) => {
		const taken = copyPlainJson(value);
		expect(taken.ok).toBe(false);
		if (!taken.ok && at !== undefined) expect(taken.at).toBe(at);
	});

	it("freezes the copy at every depth, and keeps no object it was given", () => {
		const source = { a: { b: [1, { c: 2 }] } };
		const taken = copyPlainJson(source);
		if (!taken.ok) throw new Error("refused");
		const copy = taken.copy as { a: { b: [number, { c: number }] } };
		expect(Object.isFrozen(copy)).toBe(true);
		expect(Object.isFrozen(copy.a)).toBe(true);
		expect(Object.isFrozen(copy.a.b)).toBe(true);
		expect(Object.isFrozen(copy.a.b[1])).toBe(true);
		expect(copy.a).not.toBe(source.a);
		expect(copy).toEqual(source);
	});

	it("reads each field once, an own getter's included, and copies an object two fields share once", () => {
		let reads = 0;
		const shared = {
			get x() {
				reads += 1;
				return 1;
			},
		};
		const taken = copyPlainJson({ a: shared, b: shared });
		if (!taken.ok) throw new Error("refused");
		const copy = taken.copy as { a: unknown; b: unknown };
		expect(reads).toBe(1);
		expect(copy.a).toBe(copy.b);
		expect(Object.getOwnPropertyDescriptor(copy.a, "x")).toMatchObject({ value: 1 });
	});

	it("keeps an own __proto__ as the field it is, never as the copy's prototype", () => {
		const taken = copyPlainJson(JSON.parse('{"__proto__": {"polluted": true}}'));
		if (!taken.ok) throw new Error("refused");
		expect(Object.getPrototypeOf(taken.copy)).toBe(Object.prototype);
		expect(Object.hasOwn(taken.copy as object, "__proto__")).toBe(true);
		expect((taken.copy as { polluted?: unknown }).polluted).toBeUndefined();
	});

	it("never throws, even for a Proxy that throws a value whose own traps throw it — at the top and nested", () => {
		/** A Proxy whose `getPrototypeOf` throws the Proxy itself: inspecting it as a thrown value throws again. */
		const selfThrowing = (): object => {
			const thrown: object = new Proxy(
				{},
				{
					getPrototypeOf: () => {
						throw thrown;
					},
				},
			);
			return thrown;
		};
		const hostile: readonly (readonly [string, unknown])[] = [
			[
				"ownKeys",
				new Proxy(
					{},
					{
						ownKeys: () => {
							throw selfThrowing();
						},
					},
				),
			],
			["getPrototypeOf", selfThrowing()],
			[
				"an array's length",
				new Proxy([], {
					get: (target, key, receiver) => {
						if (key === "length") throw selfThrowing();
						return Reflect.get(target, key, receiver);
					},
				}),
			],
		];
		for (const [trap, value] of hostile) {
			expect(() => copyPlainJson(value), trap).not.toThrow();
			expect(copyPlainJson(value), trap).toEqual({ ok: false, at: "" });
			expect(copyPlainJson({ a: [value] }), trap).toEqual({ ok: false, at: ".a[0]" });
		}
	});

	it("never throws, whatever a Proxy's traps do", () => {
		const throwing = new Proxy(
			{},
			{
				ownKeys: () => {
					throw new Error("ownKeys");
				},
				getPrototypeOf: () => Object.prototype,
			},
		);
		expect(copyPlainJson({ a: { b: throwing } })).toEqual({ ok: false, at: ".a.b" });
	});
});

describe("copyPlainJsonNegativeZeroAsZero — internal: -0 read as 0, as JSON writes it", () => {
	it("reads -0 as 0 at any depth, where copyPlainJson refuses it", () => {
		const taken = copyPlainJsonNegativeZeroAsZero({ a: -0, b: [-0], c: { d: -0 } });
		expect(taken.ok).toBe(true);
		if (!taken.ok) return;
		const copy = taken.copy as { a: number; b: number[]; c: { d: number } };
		expect(Object.is(copy.a, 0)).toBe(true);
		expect(Object.is(copy.b[0], 0)).toBe(true);
		expect(Object.is(copy.c.d, 0)).toBe(true);
		expect(copyPlainJson({ a: -0 })).toEqual({ ok: false, at: ".a" });
	});

	it("refuses everything else copyPlainJson refuses", () => {
		expect(copyPlainJsonNegativeZeroAsZero({ a: Number.NaN })).toEqual({ ok: false, at: ".a" });
		expect(copyPlainJsonNegativeZeroAsZero({ a: new Date(0) })).toEqual({ ok: false, at: ".a" });
	});
});
