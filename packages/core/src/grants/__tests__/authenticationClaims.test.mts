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
import { wellFormedAcr, wellFormedAmr } from "#/grants/authenticationClaims.mjs";

describe("wellFormedAmr — the amr a token may carry (#481 audit)", () => {
	it("is a non-empty array of non-empty strings, copied", () => {
		const source = ["pwd", "mfa"];
		const amr = wellFormedAmr(source);
		expect(amr).toEqual(["pwd", "mfa"]);
		expect(amr).not.toBe(source);
	});

	it.each([
		["an empty array", []],
		["an empty element", ["pwd", ""]],
		["a non-string element", ["pwd", 7]],
		["a string", "pwd"],
		["null", null],
		["undefined", undefined],
	])("is undefined for %s", (_label, value) => {
		// An `amr: []` stamped by one grant and dropped by the next is the
		// inconsistency this exists to prevent: every grant reads the same shape.
		expect(wellFormedAmr(value)).toBeUndefined();
	});
});

describe("wellFormedAcr — the acr a token may carry (#481 audit)", () => {
	it("is a non-empty string", () => {
		expect(wellFormedAcr("urn:example:mfa")).toBe("urn:example:mfa");
	});

	it.each([[""], [7], [null], [undefined], [["urn:example:mfa"]]])(
		"is undefined for %j",
		(value) => {
			expect(wellFormedAcr(value)).toBeUndefined();
		},
	);
});
