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
 * The long code (the MFA ADR's D6, D22): 16 Crockford base32 characters from
 * the CSPRNG — 80 bits — shown in four groups of four, and read as a user
 * types or pastes it: in either case, with or without the hyphens, with
 * Crockford's `O`, `I` and `L` read as the digits they stand for.
 */

import { describe, expect, it } from "vitest";
import { formatLongCode, generateLongCode, readLongCode } from "#/codes.mjs";

const CROCKFORD = /^[0-9A-HJKMNP-TV-Z]{16}$/;

describe("generateLongCode", () => {
	it("makes 16 Crockford base32 characters from 10 random bytes: 80 bits, five to a character", () => {
		const asked: number[] = [];
		const zeros = generateLongCode((size) => {
			asked.push(size);
			return Buffer.alloc(size);
		});
		expect(asked).toEqual([10]);
		expect(zeros).toBe("0000000000000000");
		expect(generateLongCode((size) => Buffer.alloc(size, 0xff))).toBe("ZZZZZZZZZZZZZZZZ");
		// 00001 in every group of five bits.
		const ones = Buffer.from([0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21]);
		expect(generateLongCode(() => ones)).toBe("1111111111111111");
	});

	it("draws from the CSPRNG by default: a new code each time, in the alphabet", () => {
		const codes = new Set(Array.from({ length: 50 }, () => generateLongCode()));
		expect(codes.size).toBe(50);
		for (const code of codes) expect(code).toMatch(CROCKFORD);
	});
});

describe("formatLongCode", () => {
	it("shows a code in four groups of four, joined by hyphens", () => {
		expect(formatLongCode("0123456789ABCDEF")).toBe("0123-4567-89AB-CDEF");
	});

	it("refuses what is not a code as generateLongCode makes one", () => {
		for (const value of [
			"0123-4567-89AB-CDEF",
			"0123456789abcdef",
			"0123456789ABCDE",
			"0123456789ABCDEU",
		]) {
			expect(() => formatLongCode(value), value).toThrow(RangeError);
		}
	});
});

describe("readLongCode", () => {
	const code = "0123456789ABCDEF";

	it("reads a code as it was shown, as it was made, and in lower case", () => {
		expect(readLongCode("0123-4567-89AB-CDEF")).toBe(code);
		expect(readLongCode(code)).toBe(code);
		expect(readLongCode("0123-4567-89ab-cdef")).toBe(code);
		expect(readLongCode("0123456789abcdef")).toBe(code);
	});

	it("reads a paste with the whitespace around it, and hyphens wherever they fall", () => {
		expect(readLongCode("  0123-4567-89AB-CDEF\n")).toBe(code);
		expect(readLongCode("01234567-89ABCDEF")).toBe(code);
	});

	it("reads O as zero and I and L as one, in either case", () => {
		expect(readLongCode("O123-4567-89AB-CDEF")).toBe(code);
		expect(readLongCode("oI23-4567-89AB-CDEF")).toBe(code);
		expect(readLongCode("0L23-4567-89AB-CDEF")).toBe(code);
		expect(readLongCode("0l23-4567-89ab-cdef")).toBe(code);
		expect(readLongCode("0i23-4567-89ab-cdef")).toBe(code);
	});

	it("refuses anything else: another length, U, a letter beyond ASCII that upper-cases to one, whitespace inside, a value that is not a string", () => {
		for (const value of [
			"",
			"0123-4567-89AB-CDE",
			"0123-4567-89AB-CDEF0",
			"0123-4567-89AB-CDEU",
			"0123-4567-89AB-CDEı",
			"0123 4567 89AB CDEF",
			"0123_4567_89AB_CDEF",
			`${"-".repeat(64)}0123456789ABCDEF`,
		]) {
			expect(readLongCode(value), JSON.stringify(value)).toBeUndefined();
		}
		for (const value of [undefined, null, 123, ["0123456789ABCDEF"], { code }]) {
			expect(readLongCode(value), JSON.stringify(value)).toBeUndefined();
		}
	});

	it("reads back every code generateLongCode makes, as made and as shown", () => {
		for (let n = 0; n < 50; n++) {
			const made = generateLongCode();
			expect(readLongCode(made)).toBe(made);
			expect(readLongCode(formatLongCode(made))).toBe(made);
			expect(readLongCode(formatLongCode(made).toLowerCase())).toBe(made);
		}
	});
});
