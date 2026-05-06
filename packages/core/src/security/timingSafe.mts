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

import { timingSafeEqual } from "node:crypto";

/**
 * Constant-time string equality.
 *
 * `===`/`!==` short-circuit on the first mismatched byte, leaking timing
 * information about how many bytes of the candidate matched the secret.
 * For PKCE `code_verifier` comparison (RFC 7636 §4.1) and OAuth 2.1 BCP
 * §4.5 this is a security defect — a network-positioned attacker can
 * iteratively recover a stored `code_challenge` byte-by-byte.
 *
 * Implementation note (Codex Delta 3 of SF-3 spec): the buffers are
 * encoded BEFORE the length check. `timingSafeEqual` requires equal-length
 * inputs, and JS string length does not equal UTF-8 byte length for
 * multi-byte code points (`"😀".length === 2` but `Buffer.byteLength("😀") === 4`).
 * Comparing byte-lengths after encoding makes the helper safe for
 * arbitrary Unicode strings and avoids a thrown `RangeError` on the rare
 * non-ASCII PKCE input.
 *
 * The byte-length difference itself is NOT a usable timing oracle for
 * PKCE: `code_verifier` length is bounded to 43–128 ASCII chars by RFC
 * 7636, so its byte-length is publicly known. For the SHA-256 base64url
 * output it is always 43 chars / 43 bytes.
 *
 * Per SF-3 + MIN-4 (v0.5.1).
 */
export function constantTimeStringEqual(a: string, b: string): boolean {
	const bufA = Buffer.from(a, "utf8");
	const bufB = Buffer.from(b, "utf8");
	if (bufA.length !== bufB.length) return false;
	return timingSafeEqual(bufA, bufB);
}
