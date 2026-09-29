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
 * Constant-time string equality, for inputs whose byte length is public
 * (PKCE `code_verifier`, `code_challenge`). `===` short-circuits on the first
 * mismatch, letting a network attacker recover a stored value byte by byte
 * (RFC 7636 §4.1, OAuth 2.1 BCP §4.5).
 *
 * Contract: NOT constant-time across different lengths; a length mismatch
 * returns early. Safe here because PKCE lengths are protocol-bounded and not
 * secret (verifier 43–128 chars, S256 challenge always 43). Do not reuse for
 * secrets whose length is sensitive; compare fixed-size digests (e.g. HMAC)
 * instead.
 *
 * A string that is not well formed never compares equal, not even to itself
 * (`false`, never a throw): UTF-8 encodes every lone surrogate as U+FFFD's
 * bytes, so `"s\uD800"` and `"s�"` would otherwise match. Callers compare
 * against server-made or well-formed protocol values, so none loses a match.
 *
 * Buffers are encoded before the length check: `timingSafeEqual` needs equal
 * byte lengths, and string length differs from UTF-8 byte length for
 * non-ASCII input.
 */
export function constantTimeStringEqual(a: string, b: string): boolean {
	// A lone surrogate encodes as U+FFFD's bytes (see the JSDoc).
	if (!a.isWellFormed() || !b.isWellFormed()) return false;
	const bufA = Buffer.from(a, "utf8");
	const bufB = Buffer.from(b, "utf8");
	// Intentional: `timingSafeEqual` throws on unequal lengths, and constant
	// time across different lengths is not this helper's contract.
	if (bufA.length !== bufB.length) return false;
	return timingSafeEqual(bufA, bufB);
}
