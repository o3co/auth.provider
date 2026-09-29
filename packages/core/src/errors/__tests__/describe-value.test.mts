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
 * `describeValue`: how a refusal names a value it was handed and cannot
 * trust — by its kind and, for a primitive, its value — without ever
 * throwing, so the refusal that names it is the error the caller sees.
 */

import { describe, expect, it } from "vitest";
import { describeValue } from "#/errors/describe-value.mjs";

describe("describeValue", () => {
	it("names a primitive by its kind and value", () => {
		expect(describeValue(undefined)).toBe("undefined");
		expect(describeValue(null)).toBe("null");
		expect(describeValue("soon")).toBe('the string "soon"');
		expect(describeValue(0)).toBe("the number 0");
		expect(describeValue(Number.NaN)).toBe("the number NaN");
		expect(describeValue(1n)).toBe("the bigint 1");
		expect(describeValue(true)).toBe("the boolean true");
		expect(describeValue(Symbol("s"))).toBe("a symbol");
		expect(describeValue(() => 1)).toBe("a function");
	});

	it("names an object by its constructor, and nothing of what it holds", () => {
		const circular: Record<string, unknown> = {};
		circular.self = circular;
		expect(describeValue(circular)).toBe("an Object");
		expect(describeValue([1, 2])).toBe("an Array");
		expect(describeValue(new Map())).toBe("a Map");
		expect(describeValue(Object.create(null))).toBe("an object");
	});

	it("never throws, whatever the value does when it is read", () => {
		const hostile = new Proxy(
			{},
			{
				getPrototypeOf() {
					throw new Error("read me not");
				},
			},
		);
		expect(describeValue(hostile)).toBe("an object");
	});
});
