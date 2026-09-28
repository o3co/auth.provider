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
 * RFC 4648 base32 without padding: how a TOTP secret is shown to the user and
 * carried in the `otpauth://` URI (the MFA ADR's F6), and how the factor keeps
 * it. Decoding is strict — the one spelling encoding produces — so a secret
 * that is not the one written is refused rather than read as another.
 */

import { describe, expect, it } from "vitest";
import { decodeBase32, encodeBase32 } from "#/totp/base32.mjs";

/** RFC 4648 §10, without the padding. */
const VECTORS: readonly (readonly [string, string])[] = [
	["", ""],
	["f", "MY"],
	["fo", "MZXQ"],
	["foo", "MZXW6"],
	["foob", "MZXW6YQ"],
	["fooba", "MZXW6YTB"],
	["foobar", "MZXW6YTBOI"],
];

describe("RFC 4648 base32, unpadded", () => {
	for (const [text, encoded] of VECTORS) {
		it(`"${text}" is "${encoded}", both ways`, () => {
			expect(encodeBase32(Buffer.from(text, "ascii"))).toBe(encoded);
			expect(decodeBase32(encoded)?.toString("ascii")).toBe(text);
		});
	}

	it("round-trips every byte value", () => {
		const bytes = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
		for (let length = 0; length <= bytes.length; length += 7) {
			const slice = bytes.subarray(0, length);
			expect(decodeBase32(encodeBase32(slice))?.equals(slice)).toBe(true);
		}
	});

	it("refuses what encoding never produces: padding, lower case, other letters, impossible lengths, stray bits", () => {
		for (const text of [
			"MY======",
			"my",
			"MZXW6 YQ",
			"MZXW1",
			"MZXW0",
			"MZXW8",
			"M",
			"MZX",
			"MZXW6Y",
			"MZ",
			"MZXR",
		]) {
			expect(decodeBase32(text), text).toBeUndefined();
		}
		expect(decodeBase32(42 as unknown as string)).toBeUndefined();
	});
});
