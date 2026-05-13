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
import { extractResourceParam } from "#/grants/_resourceIndicator.mjs";

describe("extractResourceParam", () => {
	it("returns null when resource is absent", () => {
		expect(extractResourceParam({})).toBeNull();
	});

	it("returns null when resource is empty string", () => {
		expect(extractResourceParam({ resource: "" })).toBeNull();
	});

	it("wraps a single string value in an array", () => {
		expect(extractResourceParam({ resource: "https://rs1.example" })).toEqual([
			"https://rs1.example",
		]);
	});

	it("does NOT split on commas — URIs may contain commas (RFC 8707 §5.4)", () => {
		expect(extractResourceParam({ resource: "https://a,b.example" })).toEqual([
			"https://a,b.example",
		]);
	});

	it("returns the array as-is when resource is an array of strings", () => {
		expect(extractResourceParam({ resource: ["https://r1", "https://r2"] })).toEqual([
			"https://r1",
			"https://r2",
		]);
	});

	it("returns null for a non-string, non-array value (defensive)", () => {
		expect(extractResourceParam({ resource: 42 as unknown })).toBeNull();
	});

	it("returns null when the array contains a non-string element (defensive against mixed-type arrays)", () => {
		expect(extractResourceParam({ resource: ["https://r1", 42] as unknown })).toBeNull();
	});
});
