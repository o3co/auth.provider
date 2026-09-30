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
 * The long code (the MFA ADR's D6, D22): every 80-bit code the package
 * issues — a recovery code, the account-email proof, an email factor's
 * enrollment code. Made from 10 bytes of the CSPRNG as 16 Crockford base32
 * characters, shown in four groups of four, and read as a user types or
 * pastes it: either case, hyphens anywhere, whitespace around it, and `O`,
 * `I`, `L` read as the digits they stand for. Reading is ASCII first, so no
 * letter beyond ASCII can upper-case into the alphabet.
 */

import { randomBytes } from "node:crypto";

/** Crockford's base32 alphabet: no `I`, `L`, `O` or `U`. */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** The bytes a code is made from: 80 bits, five to a character. */
const CODE_BYTES = 10;

/** A code as made: 16 characters of the alphabet. */
const CODE = /^[0-9A-HJKMNP-TV-Z]{16}$/;

/** What is read before anything else: the alphabet, its substitutes, either case, and hyphens. */
const TYPED = /^[0-9A-Za-z-]+$/;

/** The longest text read as a code: its 16 characters and room for hyphens. */
const TYPED_MAX_LENGTH = 64;

/** Crockford's substitutions: what a user may type for a digit. */
const SUBSTITUTES: Readonly<Record<string, string>> = { O: "0", I: "1", L: "1" };

/** A new long code: 10 bytes from `random` (the CSPRNG), as 16 Crockford base32 characters. */
export function generateLongCode(
	random: (size: number) => Buffer = (size) => randomBytes(size),
): string {
	const bytes = random(CODE_BYTES);
	let code = "";
	let bits = 0;
	let value = 0;
	for (const byte of bytes.subarray(0, CODE_BYTES)) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			code += ALPHABET[(value >>> bits) & 31];
		}
		value &= (1 << bits) - 1;
	}
	if (!CODE.test(code)) throw new RangeError("a long code is made from 10 random bytes");
	return code;
}

/** `code`, as made, in four groups of four joined by hyphens; a `RangeError` for anything else. */
export function formatLongCode(code: string): string {
	if (typeof code !== "string" || !CODE.test(code)) {
		throw new RangeError("formatLongCode takes a long code as generateLongCode makes it");
	}
	return `${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}-${code.slice(12)}`;
}

/** `input` read as a long code, as made; `undefined` when it is not one. */
export function readLongCode(input: unknown): string | undefined {
	if (typeof input !== "string") return undefined;
	const typed = input.trim();
	if (typed.length > TYPED_MAX_LENGTH || !TYPED.test(typed)) return undefined;
	const code = typed
		.replaceAll("-", "")
		.toUpperCase()
		.replace(/[OIL]/g, (letter) => SUBSTITUTES[letter] as string);
	return CODE.test(code) ? code : undefined;
}
