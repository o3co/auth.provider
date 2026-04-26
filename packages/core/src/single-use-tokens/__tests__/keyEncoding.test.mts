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
import { canonicalKey } from "#/single-use-tokens/keyEncoding.mjs";

describe("canonicalKey", () => {
	it("encodes scope and key with length prefixes and a delimiter", () => {
		expect(canonicalKey("webauthn:auth", "abc")).toBe("13:webauthn:auth|3:abc");
	});

	it("is deterministic", () => {
		expect(canonicalKey("a", "b")).toBe(canonicalKey("a", "b"));
	});

	it("produces distinct keys for shape-collision pairs (length-prefix property)", () => {
		// Without length prefixes, "ab" + ":" + "cd" and "abcd" + "" share the same
		// concatenation. Length-prefixed encoding MUST keep them distinct.
		const a = canonicalKey("ab", ":cd");
		const b = canonicalKey("abcd", "");
		expect(a).not.toBe(b);
	});

	it("produces distinct keys for delimiter-collision pairs", () => {
		// "::" delimiter naive: ("a", ":b") and ("a:", "b") collide via "a:::b" vs
		// "a:::b". With length-prefix encoding they MUST be distinct.
		const a = canonicalKey("a", ":b");
		const b = canonicalKey("a:", "b");
		expect(a).not.toBe(b);
	});

	it("handles empty scope and empty key", () => {
		expect(canonicalKey("", "")).toBe("0:|0:");
		expect(canonicalKey("", "x")).toBe("0:|1:x");
		expect(canonicalKey("x", "")).toBe("1:x|0:");
	});

	it("uses JS string length (UTF-16 code units), not byte length", () => {
		// "🦀" is one codepoint U+1F980, two UTF-16 code units, four UTF-8 bytes.
		// We document and assert UTF-16 code units (String.prototype.length).
		const s = "🦀";
		expect(s.length).toBe(2); // sanity: confirm UTF-16 length
		expect(canonicalKey(s, "")).toBe("2:🦀|0:");
	});
});
