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
 * Parity tests for the webauthn-internal extractResourceParam helper.
 *
 * The webauthn package duplicates packages/oauth/src/grants/_resourceIndicator.mts
 * (cross-package private import avoided — see PARITY comment in the source file).
 * These tests exercise the same 7 cases as the oauth original so future drift
 * between the two copies is caught at test time rather than during code review.
 *
 * PARITY SOURCE: packages/oauth/src/grants/__tests__/_resourceIndicator.test.mts
 * Wave 2 consolidation candidate: issue #173.
 *
 * Cross-refs: Claude Round 1 I4 / Wave 2 consolidation candidate (issue #173)
 */

import { describe, expect, it } from "vitest";
import { extractResourceParam } from "../_resourceIndicator.mjs";

describe("extractResourceParam (webauthn — parity with oauth copy)", () => {
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
