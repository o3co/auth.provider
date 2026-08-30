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
 * `user_code` / `device_code` generation and normalisation (RFC 8628 §6.1,
 * §5.1, §5.2).
 */

import { describe, expect, it } from "vitest";
import {
	formatUserCode,
	generateDeviceCode,
	generateUserCode,
	normaliseUserCode,
	USER_CODE_ALPHABET,
	USER_CODE_LENGTH,
} from "../userCode.mjs";

describe("user code alphabet (RFC 8628 §6.1)", () => {
	it("contains no vowels, so no code can spell a word", () => {
		expect(USER_CODE_ALPHABET).not.toMatch(/[AEIOU]/);
	});

	it("contains no digits, so 0/O, 1/I, 5/S, 8/B and 2/Z cannot be confused", () => {
		// §6.1: "avoid character sets that contain two or more characters that
		// can easily be confused".
		expect(USER_CODE_ALPHABET).not.toMatch(/[0-9]/);
	});

	it("has 20 distinct characters, which is what 34.5 bits at length 8 assumes", () => {
		expect(new Set(USER_CODE_ALPHABET).size).toBe(20);
		// §5.1's worked example is "an 8-character base 20 user code (with
		// roughly 34.5 bits of entropy)". Asserted as the band the RFC's
		// rate-limit budget is computed from rather than to a decimal place —
		// the number that matters is which side of 34 bits this lands on.
		const bits = Math.log2(USER_CODE_ALPHABET.length) * USER_CODE_LENGTH;
		expect(bits).toBeGreaterThan(34);
		expect(bits).toBeLessThan(35);
	});
});

describe("generateUserCode", () => {
	it("produces a display-formatted code drawn only from the alphabet", () => {
		for (let i = 0; i < 50; i++) {
			const code = generateUserCode();
			expect(code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
		}
	});

	it("does not visibly favour any part of the alphabet", () => {
		// A `randomBytes()[i] % 20` implementation biases toward the first 16
		// characters — 256 is not a multiple of 20 — costing about a bit of the
		// 34.5 the rate-limit budget is calculated from. Crude, but a 16/20
		// split that large shows up immediately at this sample size.
		const counts = new Map<string, number>();
		for (let i = 0; i < 4000; i++) {
			for (const ch of normaliseUserCode(generateUserCode()) ?? "") {
				counts.set(ch, (counts.get(ch) ?? 0) + 1);
			}
		}
		const first16 = USER_CODE_ALPHABET.slice(0, 16);
		const biasedTotal = [...first16].reduce((sum, ch) => sum + (counts.get(ch) ?? 0), 0);
		const total = [...counts.values()].reduce((a, b) => a + b, 0);
		// Unbiased share of the first 16 of 20 is 0.8; the modulo bias pushes it
		// to about 0.875.
		expect(biasedTotal / total).toBeLessThan(0.84);
	});
});

describe("normaliseUserCode", () => {
	it("accepts the code as displayed", () => {
		expect(normaliseUserCode("BCDF-GHJK")).toBe("BCDFGHJK");
	});

	it("accepts lower case, spaces, and no separator at all", () => {
		// All three are the same code to the person typing it.
		expect(normaliseUserCode("bcdf-ghjk")).toBe("BCDFGHJK");
		expect(normaliseUserCode("BCDF GHJK")).toBe("BCDFGHJK");
		expect(normaliseUserCode("bcdfghjk")).toBe("BCDFGHJK");
	});

	it("rejects a character outside the alphabet instead of stripping it", () => {
		// A `0` typed for an `O` is a mistake. Stripping it would turn an
		// 8-character mistake into a 7-character lookup, which either fails for
		// a reason the user cannot see or matches a different code.
		expect(normaliseUserCode("BCDF-GHJ0")).toBeNull();
		expect(normaliseUserCode("BCDFGHJ1")).toBeNull();
		expect(normaliseUserCode("AEIOUBCD")).toBeNull();
	});

	it("rejects a code of the wrong length", () => {
		expect(normaliseUserCode("BCDFGHJ")).toBeNull();
		expect(normaliseUserCode("BCDFGHJKL")).toBeNull();
		expect(normaliseUserCode("")).toBeNull();
	});

	it("round-trips with formatUserCode", () => {
		const raw = "BCDFGHJK";
		expect(normaliseUserCode(formatUserCode(raw))).toBe(raw);
	});
});

describe("generateDeviceCode", () => {
	it("is high-entropy and url-safe (§5.2)", () => {
		const code = generateDeviceCode();
		expect(code).toMatch(/^[A-Za-z0-9_-]+$/);
		// 32 bytes base64url — 256 bits, no padding.
		expect(code).toHaveLength(43);
	});

	it("does not repeat", () => {
		const codes = new Set(Array.from({ length: 500 }, () => generateDeviceCode()));
		expect(codes.size).toBe(500);
	});
});
