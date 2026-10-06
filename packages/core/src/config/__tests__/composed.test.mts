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

/**
 * How boot's one composed parse lays a schema's parse over what was written,
 * so a key no schema declares is kept.
 */

import { describe, expect, it } from "vitest";
import { overlayConfig } from "../composed.mjs";

/** `value` frozen all the way down, so a change to it throws. */
function deepFreeze<T>(value: T): T {
	if (typeof value === "object" && value !== null) {
		for (const child of Object.values(value)) deepFreeze(child);
		Object.freeze(value);
	}
	return value;
}

describe("overlayConfig — a parse laid over what was written", () => {
	it("merges objects key by key, the upper value winning, a key only the lower has kept", () => {
		expect(
			overlayConfig(
				{ a: { kept: 1, both: "raw" }, list: [1, 2, 3] },
				{ a: { both: 2 }, list: [9] },
			),
		).toEqual({ a: { kept: 1, both: 2 }, list: [9] });
	});

	it("removes a key the upper object holds as undefined: the schema made nothing of the value", () => {
		const merged = overlayConfig({ a: "", b: 1 }, { a: undefined }) as Record<string, unknown>;
		expect(merged).toEqual({ b: 1 });
		expect(Object.hasOwn(merged, "a")).toBe(false);
	});

	it("keeps a key the upper object does not hold: the schema did not declare it", () => {
		expect(overlayConfig({ a: "x", b: 1 }, { b: 2 })).toEqual({ a: "x", b: 2 });
	});

	it("answers the lower value whole when there is no upper one", () => {
		expect(overlayConfig({ a: 1 }, undefined)).toEqual({ a: 1 });
	});

	it("takes a value that is not a plain object whole", () => {
		const url = new URL("https://idp.example/");
		expect(overlayConfig({ a: { href: "x" } }, { a: url })).toEqual({ a: url });
		expect((overlayConfig({ a: { href: "x" } }, { a: url }) as { a: unknown }).a).toBe(url);
	});

	it("changes neither input", () => {
		const under = deepFreeze({ a: { kept: 1, both: "raw" }, widget: { size: "3" } });
		const over = deepFreeze({ a: { both: 2 }, b: { added: true } });
		const before = JSON.stringify([under, over]);
		expect(overlayConfig(under, over)).toEqual({
			a: { kept: 1, both: 2 },
			widget: { size: "3" },
			b: { added: true },
		});
		expect(JSON.stringify([under, over])).toBe(before);
	});

	it("keeps a key named __proto__ as a key", () => {
		const lower = JSON.parse('{"__proto__": {"polluted": true}}') as Record<string, unknown>;
		const merged = overlayConfig(lower, { a: 1 }) as Record<string, unknown>;
		expect(Object.hasOwn(merged, "__proto__")).toBe(true);
		expect(({} as Record<string, unknown>).polluted).toBeUndefined();
	});
});
