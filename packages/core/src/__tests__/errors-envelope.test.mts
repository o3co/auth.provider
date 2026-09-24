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
import { errorEnvelope, isErrorCode, sanitizeErrorText } from "../errors/envelope.mjs";

describe("AS-1/AS-2 errorEnvelope helper (RFC 6749 §5.2)", () => {
	it("includes error_description and error_uri when provided", () => {
		const e = errorEnvelope("invalid_grant", "Token expired", "https://docs.example.com");
		expect(e).toEqual({
			error: "invalid_grant",
			error_description: "Token expired",
			error_uri: "https://docs.example.com",
		});
	});

	it("omits optional fields when undefined", () => {
		const e = errorEnvelope("not_found");
		expect(e).toEqual({ error: "not_found" });
		expect(e).not.toHaveProperty("error_description");
		expect(e).not.toHaveProperty("error_uri");
	});

	it("includes error_description without error_uri", () => {
		const e = errorEnvelope("server_error", "Session regeneration failed");
		expect(e).toEqual({
			error: "server_error",
			error_description: "Session regeneration failed",
		});
		expect(e).not.toHaveProperty("error_uri");
	});

	it("treats undefined description as omission, not as a present empty value", () => {
		const e = errorEnvelope("rate_limited", undefined);
		expect(Object.keys(e).sort()).toEqual(["error"]);
	});

	it("treats empty-string description and uri as omissions", () => {
		const e = errorEnvelope("rate_limited", "", "");
		expect(e).toEqual({ error: "rate_limited" });
		expect(e).not.toHaveProperty("error_description");
		expect(e).not.toHaveProperty("error_uri");
	});
});

// RFC 6749 §5.2 (and §4.1.2.1 for the authorization endpoint): `error` is
// 1*NQSCHAR and `error_description` is *(%x20-21 / %x23-5B / %x5D-7E) — the
// same characters: printable ASCII without `"` and `\`.
describe("RFC 6749 error text", () => {
	const allowed = Array.from({ length: 0x7f - 0x20 }, (_, i) => String.fromCharCode(0x20 + i))
		.filter((c) => c !== '"' && c !== "\\")
		.join("");

	describe("sanitizeErrorText", () => {
		it("keeps every character the RFC allows", () => {
			expect(sanitizeErrorText(allowed)).toBe(allowed);
		});

		it.each([
			["a double quote (%x22)", 'a"b', "a?b"],
			["a backslash (%x5C)", "a\\b", "a?b"],
			["a control character", "a\u0000b\u001fc\u007fd", "a?b?c?d"],
			["a line break", "a\r\nb", "a??b"],
			["a non-ASCII character", "a\u00e9b\u2014c", "a?b?c"],
			["a character outside the BMP, as one character", "a\u{1F600}b", "a?b"],
		])("replaces %s with '?'", (_label, input, expected) => {
			expect(sanitizeErrorText(input)).toBe(expected);
		});
	});

	describe("isErrorCode", () => {
		it.each(["invalid_request", "access_denied", allowed])("accepts %j", (code) => {
			expect(isErrorCode(code)).toBe(true);
		});

		it.each([
			["the empty string", ""],
			["a double quote", 'bad "code"'],
			["a backslash", "bad\\code"],
			["a control character", "bad\ncode"],
			["non-ASCII", "d\u00e9ny"],
			["a non-string", 42],
			["undefined", undefined],
		])("refuses %s", (_label, code) => {
			expect(isErrorCode(code)).toBe(false);
		});
	});
});
