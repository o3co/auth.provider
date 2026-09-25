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

// How a configured key becomes key material: canonical base64 of exactly 32
// bytes, and nothing that has to be tidied up first.

import { describe, expect, it } from "vitest";
import { decodeSealingKey, SEALING_KEY_BYTES } from "#/sealing/keyRing.mjs";

const KEY = Buffer.alloc(32, 0xa5).toString("base64");

describe("decodeSealingKey", () => {
	it("reads canonical base64 of 32 bytes as those bytes", () => {
		expect(SEALING_KEY_BYTES).toBe(32);
		const random = Buffer.from(
			"1f8b0a7c3e5d9a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6a8b",
			"hex",
		);
		expect(decodeSealingKey(random.toString("base64"))?.equals(random)).toBe(true);
		expect(decodeSealingKey(KEY)?.equals(Buffer.alloc(32, 0xa5))).toBe(true);
	});

	it("refuses a value that has to be tidied up before it can be read: whitespace anywhere", () => {
		// `Buffer.from(…, "base64")` ignores embedded whitespace, so a key pasted
		// out of a file, or wrapped by a secret manager, would otherwise read as
		// the key the operator did not check.
		for (const encoded of [
			`${KEY}\n`,
			` ${KEY}`,
			`${KEY.slice(0, 20)}\n${KEY.slice(20)}`,
			`${KEY}\t`,
		]) {
			expect(decodeSealingKey(encoded), JSON.stringify(encoded)).toBeUndefined();
		}
	});

	it("refuses what is not canonical base64: base64url, missing or extra padding, stray characters", () => {
		const url = Buffer.alloc(32, 0xff).toString("base64url");
		for (const encoded of [
			url,
			KEY.replace(/=+$/, ""),
			`${KEY}=`,
			`${KEY.slice(0, -2)}!=`,
			"not base64!!",
			"",
		]) {
			expect(decodeSealingKey(encoded), JSON.stringify(encoded)).toBeUndefined();
		}
	});

	it("refuses key material that is not exactly 32 bytes", () => {
		for (const bytes of [0, 16, 31, 33, 64]) {
			expect(
				decodeSealingKey(Buffer.alloc(bytes, 1).toString("base64")),
				String(bytes),
			).toBeUndefined();
		}
	});
});
