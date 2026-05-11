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
import { constantTimeStringEqual } from "../timingSafe.mjs";

describe("constantTimeStringEqual (SF-3 + MIN-4)", () => {
	it("returns true for two equal strings", () => {
		expect(constantTimeStringEqual("abc", "abc")).toBe(true);
	});

	it("returns false for two different strings of the same length", () => {
		expect(constantTimeStringEqual("abc", "abd")).toBe(false);
	});

	it("returns false for strings that differ only in the last byte (near-miss)", () => {
		// PKCE base64url-encoded SHA-256 outputs are always 43 chars; verify the
		// helper still returns false when the difference is at the very end —
		// rules out an early-return bug that would mask near-miss failures
		// (the whole point of the timing-safe primitive).
		const a = `${"a".repeat(42)}x`;
		const b = `${"a".repeat(42)}y`;
		expect(constantTimeStringEqual(a, b)).toBe(false);
	});

	it("returns false for strings of different length without throwing", () => {
		// `crypto.timingSafeEqual` throws when buffer lengths differ; the
		// helper must short-circuit on the byte-length comparison first
		// (Codex Delta 3: encode-then-length, not length-then-encode).
		expect(() => constantTimeStringEqual("abc", "ab")).not.toThrow();
		expect(constantTimeStringEqual("abc", "ab")).toBe(false);
	});

	it("returns true for two empty strings", () => {
		expect(constantTimeStringEqual("", "")).toBe(true);
	});

	it("returns false when one string is empty and the other is not", () => {
		expect(constantTimeStringEqual("", "x")).toBe(false);
		expect(constantTimeStringEqual("x", "")).toBe(false);
	});

	it("uses byte-length (UTF-8) for the length comparison, not JS string length", () => {
		// Codex Delta 3: a multi-byte character (e.g. emoji) has JS string
		// length 2 but UTF-8 byte length 4. The helper encodes first and
		// compares byte-lengths so `timingSafeEqual` (which requires equal
		// buffer lengths) never throws on Unicode input.
		const emoji = "😀"; // JS length 2, UTF-8 length 4
		const ascii = "ab"; // JS length 2, UTF-8 length 2
		expect(() => constantTimeStringEqual(emoji, ascii)).not.toThrow();
		expect(constantTimeStringEqual(emoji, ascii)).toBe(false);
	});
});
