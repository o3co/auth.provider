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

import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Compute the `ath` claim value for an access token — RFC 9449 §4.2.
 *
 * `base64url(SHA-256(ASCII(access token)))`, unpadded, as a JWT claim value
 * must be. The digest is over the token *as transmitted*: the token is an
 * opaque string to this layer, so no decoding or normalisation happens.
 */
export const computeAth = async (accessToken: string): Promise<string> => {
	return createHash("sha256").update(accessToken, "ascii").digest("base64url");
};

/**
 * Whether a proof's `ath` binds it to this access token.
 *
 * Compared in constant time. The value is not a secret — an attacker holding
 * the token can compute it — but the comparison sits on a path an attacker can
 * drive with chosen input, and a short-circuiting compare there is the kind of
 * thing that is cheap to avoid and awkward to explain later.
 */
export const athMatches = async (ath: string, accessToken: string): Promise<boolean> => {
	const expected = Buffer.from(await computeAth(accessToken), "utf8");
	const presented = Buffer.from(ath, "utf8");
	// timingSafeEqual throws on length mismatch, which is itself observable —
	// but a differing length means a differing digest regardless, and both
	// operands are fixed-width for well-formed input.
	if (expected.length !== presented.length) return false;
	return timingSafeEqual(expected, presented);
};
