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

// How a federation grant's credential is sealed (#593, D16): in core's `v2`
// key-ring envelope (`sealing/`), whose own contract is tested there, bound
// to this store's purpose `o3co:redis:v2`. What is redis's own, and tested
// here, is that binding — the names the store calls the envelope by and the
// header every grant at rest was sealed under — and that the store's two
// formats, this one and the session-bound token store's `v1`, never read
// each other. The fixture of envelopes sealed before the envelope moved is
// in `crypto-v2.sealed-before-the-move.test.mts`.

import { createCipheriv } from "node:crypto";
import { openWithKeyRing, type SealingKeyRing, sealWithKeyRing } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	decryptTokenField,
	encryptTokenField,
	openSealedCredential,
	sealCredential,
} from "#/internal/crypto.mjs";

const key = (byte: number): Buffer => Buffer.alloc(32, byte);
const RING: SealingKeyRing = [
	{ id: "k-2026-09", key: key(2) },
	{ id: "k-2026-03", key: key(1) },
];
const RECORD = Buffer.from("the record this credential belongs to", "utf8");

const u32 = (value: number): Buffer => {
	const out = Buffer.alloc(4);
	out.writeUInt32BE(value);
	return out;
};

describe("a federation grant credential is core's v2 envelope under the purpose o3co:redis:v2", () => {
	it("is sealed and opened by the store's names as core seals and opens that purpose", () => {
		const binding = { purpose: "o3co:redis:v2", record: RECORD };
		expect(openWithKeyRing(sealCredential("rt-1", RING, RECORD), RING, binding)).toStrictEqual({
			state: "ok",
			value: "rt-1",
			keyId: "k-2026-09",
		});
		expect(
			openSealedCredential(sealWithKeyRing("rt-2", RING, binding), RING, RECORD),
		).toStrictEqual({ state: "ok", value: "rt-2", keyId: "k-2026-09" });
		// Under any other purpose it is another value, and does not open.
		const other = sealWithKeyRing("rt-3", RING, { purpose: "o3co:redis:v3", record: RECORD });
		expect(openSealedCredential(other, RING, RECORD)).toStrictEqual({ state: "unreadable" });
	});

	it("opens a vector sealed by hand under the header every grant at rest was sealed with", () => {
		// `o3co:redis:v2` NUL, then the key ID and the record, each after a
		// 32-bit big-endian length: the header the store wrote before the
		// envelope moved to core, and so the one it must keep reading.
		const material = key(4);
		const iv = Buffer.alloc(12, 5);
		const kid = Buffer.from("k-hand", "utf8");
		const cipher = createCipheriv("aes-256-gcm", material, iv);
		cipher.setAAD(
			Buffer.concat([
				Buffer.from("o3co:redis:v2\0", "ascii"),
				u32(kid.length),
				kid,
				u32(RECORD.length),
				RECORD,
			]),
		);
		const ct = Buffer.concat([cipher.update("rt-by-hand", "utf8"), cipher.final()]);
		const envelope = [
			"v2",
			kid.toString("base64url"),
			iv.toString("base64url"),
			ct.toString("base64url"),
			cipher.getAuthTag().toString("base64url"),
		].join(".");
		expect(openSealedCredential(envelope, [{ id: "k-hand", key: material }], RECORD)).toStrictEqual(
			{ state: "ok", value: "rt-by-hand", keyId: "k-hand" },
		);
	});
});

describe("the grant store's v2 and the token store's v1 pass each other by", () => {
	it("does not read a v1 envelope as a credential", () => {
		const v1 = encryptTokenField("rt-1", key(1), "aad");
		expect(openSealedCredential(v1, RING, RECORD)).toStrictEqual({ state: "unreadable" });
	});

	it("is not read by the v1 reader, which keeps working as it did", () => {
		const sealed = sealCredential("rt-1", RING, RECORD);
		expect(() => decryptTokenField(sealed, key(2), RECORD)).toThrow(/envelope/);
		// The session-bound store's records were sealed with v1.
		const v1 = encryptTokenField("rt-1", key(1), "aad");
		expect(decryptTokenField(v1, key(1), "aad")).toBe("rt-1");
	});
});
