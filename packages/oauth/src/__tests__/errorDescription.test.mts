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
import { sanitizeErrorDescription } from "#/errorDescription.mjs";

// RFC 6749 §5.2 (and §4.1.2.1 for the authorization endpoint):
// error_description = %x20-21 / %x23-5B / %x5D-7E.
describe("sanitizeErrorDescription", () => {
	it("keeps every character the RFC allows", () => {
		const allowed = Array.from({ length: 0x7f - 0x20 }, (_, i) => String.fromCharCode(0x20 + i))
			.filter((c) => c !== '"' && c !== "\\")
			.join("");
		expect(sanitizeErrorDescription(allowed)).toBe(allowed);
	});

	it.each([
		["a double quote (%x22)", 'a"b', "a?b"],
		["a backslash (%x5C)", "a\\b", "a?b"],
		["a control character", "a\u0000b\u001fc\u007fd", "a?b?c?d"],
		["a line break", "a\r\nb", "a??b"],
		["a non-ASCII character", "aéb—c", "a?b?c"],
		["a character outside the BMP, as one character", "a\u{1F600}b", "a?b"],
	])("replaces %s with '?'", (_label, input, expected) => {
		expect(sanitizeErrorDescription(input)).toBe(expected);
	});
});
