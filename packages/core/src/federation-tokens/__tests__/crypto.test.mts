/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import { decryptTokenField, encryptTokenField } from "../crypto.mjs";

const key = Buffer.alloc(32, 1); // 32-byte key for AES-256
const plaintext = "ya29.federation-refresh-token-example";

describe("encryptTokenField / decryptTokenField", () => {
	it("roundtrips a plaintext", () => {
		const ct = encryptTokenField(plaintext, key);
		expect(ct).not.toContain(plaintext);
		expect(decryptTokenField(ct, key)).toBe(plaintext);
	});

	it("produces different ciphertext each call (random IV)", () => {
		const a = encryptTokenField(plaintext, key);
		const b = encryptTokenField(plaintext, key);
		expect(a).not.toBe(b);
	});

	it("tampering fails authentication", () => {
		const ct = encryptTokenField(plaintext, key);
		const parts = ct.split(".");
		// Flip one bit in the ciphertext section.
		const ctBuf = Buffer.from(parts[2]!, "base64url");
		ctBuf[0] = ctBuf[0]! ^ 0x01;
		const tampered = [parts[0], parts[1], ctBuf.toString("base64url"), parts[3]].join(".");
		expect(() => decryptTokenField(tampered, key)).toThrow();
	});

	it("rejects wrong key", () => {
		const ct = encryptTokenField(plaintext, key);
		const wrong = Buffer.alloc(32, 2);
		expect(() => decryptTokenField(ct, wrong)).toThrow();
	});

	it("rejects non-32-byte keys", () => {
		const short = Buffer.alloc(16);
		expect(() => encryptTokenField(plaintext, short)).toThrow(/32 bytes/);
	});
});
