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
import {
	checkSealingKeyRing,
	decodeSealingKey,
	isSealingKeyId,
	SEALING_KEY_BYTES,
	type SealingKeyRing,
} from "#/sealing/keyRing.mjs";

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

/** What `run` threw: its exact class and its message. */
const refusal = (run: () => unknown): { class: unknown; message: string } => {
	try {
		run();
	} catch (err) {
		return { class: (err as Error).constructor, message: (err as Error).message };
	}
	throw new Error("expected a refusal");
};

describe("isSealingKeyId", () => {
	it("is 1 to 64 characters of A-Za-z0-9_-, and a string", () => {
		for (const id of ["k", "k-2026_09", "Z".repeat(64)]) expect(isSealingKeyId(id), id).toBe(true);
		for (const id of ["", "k.2", "k 2", "k\n", "x".repeat(65), undefined, null, 12, ["k"]]) {
			expect(isSealingKeyId(id), JSON.stringify(id)).toBe(false);
		}
	});
});

describe("checkSealingKeyRing", () => {
	const material = Buffer.alloc(32, 1);

	it("passes a ring of distinct, well-formed ids and 32-byte Buffers, and an empty one", () => {
		// Whether a ring may be empty is its reader's to say.
		expect(() =>
			checkSealingKeyRing(
				[
					{ id: "k-new", key: material },
					{ id: "k-old", key: Buffer.alloc(32, 2) },
				],
				"mfa.encryptionKeys",
			),
		).not.toThrow();
		expect(() => checkSealingKeyRing([], "mfa.encryptionKeys")).not.toThrow();
	});

	it("refuses as a RangeError prefixed with the setting it was given, naming the entry", () => {
		const cases: ReadonlyArray<readonly [string, SealingKeyRing, string]> = [
			[
				"an id outside the rule, named by its index",
				[
					{ id: "k-1", key: material },
					{ id: "k.2", key: material },
				],
				"mfa.encryptionKeys has an encryption key id at index 1 that does not match ^[A-Za-z0-9_-]{1,64}$",
			],
			[
				"a duplicate id, named by the index of the second",
				[
					{ id: "k-1", key: material },
					{ id: "k-1", key: Buffer.alloc(32, 2) },
				],
				"mfa.encryptionKeys has a duplicate encryption key id at index 1",
			],
			[
				"a key that is not 32 bytes, named by its index",
				[
					{ id: "k-0", key: material },
					{ id: "k-1", key: Buffer.alloc(16, 1) },
				],
				"mfa.encryptionKeys has an encryption key at index 1 that is not a Buffer of 32 bytes",
			],
			[
				"a key that is not a Buffer: a 32-character string would be used as its UTF-8 bytes",
				[{ id: "k-1", key: "k".repeat(32) as unknown as Buffer }],
				"mfa.encryptionKeys has an encryption key at index 0 that is not a Buffer of 32 bytes",
			],
		];
		for (const [what, ring, message] of cases) {
			expect(
				refusal(() => checkSealingKeyRing(ring, "mfa.encryptionKeys")),
				what,
			).toStrictEqual({
				class: RangeError,
				message,
			});
		}
	});

	it("never quotes an id, even one that passes the rule: an operator who swapped id and key would see the key", () => {
		// A 32-byte key spelled in hex (64 characters) or in unpadded base64url
		// (43) passes the id rule, so passing it is no sign an id is not key
		// material. Every refusal names the entry by its index instead.
		const hex = material.toString("hex");
		const base64url = material.toString("base64url");
		const padded = material.toString("base64");
		for (const swapped of [hex, base64url]) {
			expect(isSealingKeyId(swapped), swapped).toBe(true);
			for (const ring of [
				[{ id: swapped, key: "k-1" as unknown as Buffer }],
				[
					{ id: swapped, key: material },
					{ id: swapped, key: material },
				],
			]) {
				const { message } = refusal(() => checkSealingKeyRing(ring, "mfa.encryptionKeys"));
				expect(message, swapped).not.toContain(swapped);
			}
		}
		const { message } = refusal(() =>
			checkSealingKeyRing([{ id: padded, key: material }], "mfa.encryptionKeys"),
		);
		expect(message).not.toContain(padded);
	});
});
