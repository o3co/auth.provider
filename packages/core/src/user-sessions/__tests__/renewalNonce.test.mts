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

/** The renewal nonce: minted from the CSPRNG, one spelling, never repeated. */

import { describe, expect, it } from "vitest";
import {
	isRenewalNonce,
	newRenewalNonce,
	RENEWAL_NONCE_BYTES,
} from "#/user-sessions/renewalNonce.mjs";

describe("the renewal nonce", () => {
	it("is 128 bits, base64url, 22 characters, and one isRenewalNonce reads as one", () => {
		expect(RENEWAL_NONCE_BYTES).toBe(16);
		const nonce = newRenewalNonce();
		expect(nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
		expect(Buffer.from(nonce, "base64url")).toHaveLength(RENEWAL_NONCE_BYTES);
		expect(isRenewalNonce(nonce)).toBe(true);
	});

	it("is never minted twice", () => {
		const minted = new Set(Array.from({ length: 1_000 }, newRenewalNonce));
		expect(minted.size).toBe(1_000);
	});

	it.each([
		["a shorter string", "abc"],
		["a longer one", "A".repeat(23)],
		["padding", `${"A".repeat(20)}==`],
		["a character outside base64url", `${"A".repeat(21)}+`],
		["an empty string", ""],
		["a number", 7],
		["undefined", undefined],
	])("is not %s", (_label, value) => {
		expect(isRenewalNonce(value)).toBe(false);
	});
});
