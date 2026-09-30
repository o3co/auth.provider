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

/** `httpSettingsCorsOrigins`: what the CORS mount reads of a held `httpSettings` slot. */

import { describe, expect, it } from "vitest";
import { httpSettingsCorsOrigins } from "../http-settings.mjs";

describe("httpSettingsCorsOrigins", () => {
	it("answers the slot's origins as a frozen copy", () => {
		const list = ["https://app.example"];
		const origins = httpSettingsCorsOrigins({ cors: { allowedOrigins: list } });
		expect(origins).toEqual(["https://app.example"]);
		expect(Object.isFrozen(origins)).toBe(true);
		list.push("https://later.example");
		expect(origins).toEqual(["https://app.example"]);
	});

	it.each([
		["null", null],
		["a string", "https://app.example"],
		["a list", ["https://app.example"]],
	])("refuses a slot holding %s rather than a settings object", (_what, value) => {
		expect(() => httpSettingsCorsOrigins(value)).toThrow(
			/^httpSettings must be the settings object/,
		);
	});

	it.each([
		["no cors", {}],
		["cors with no list", { cors: {} }],
		["a list that is not one", { cors: { allowedOrigins: "https://app.example" } }],
	])("refuses a slot with %s, naming cors.allowedOrigins", (_what, value) => {
		expect(() => httpSettingsCorsOrigins(value)).toThrow(
			/^httpSettings\.cors\.allowedOrigins must be a list of serialized origins/,
		);
	});

	it("refuses an entry that is not a string, naming its index", () => {
		expect(() =>
			httpSettingsCorsOrigins({ cors: { allowedOrigins: ["https://app.example", 42] } }),
		).toThrow(/^httpSettings\.cors\.allowedOrigins\[1\] is not a string/);
	});

	it("refuses a member whose read throws, naming it, with the throw as the cause", () => {
		const boom = new Error("boom");
		const value = {
			get cors(): never {
				throw boom;
			},
		};
		let caught: unknown;
		try {
			httpSettingsCorsOrigins(value);
		} catch (err) {
			caught = err;
		}
		expect(caught).toBeInstanceOf(RangeError);
		expect((caught as Error).message).toMatch(/^httpSettings\.cors could not be read/);
		expect((caught as Error).cause).toBe(boom);
	});
});
