/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import { decryptTokenField, encryptTokenField } from "../../src/internal/crypto.mjs";

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
		expect(parts).toHaveLength(4);
		const [ver, iv, ct0, tag] = parts as [string, string, string, string];
		// Flip one bit in the ciphertext section.
		const ctBuf = Buffer.from(ct0, "base64url");
		const first = ctBuf[0] ?? 0;
		ctBuf[0] = first ^ 0x01;
		const tampered = [ver, iv, ctBuf.toString("base64url"), tag].join(".");
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

// #293: the federation-token store binds each envelope ciphertext to the Redis
// key it lives under, so a value copied to another session's key is refused.
// These pin the primitive that binding rests on.
describe("encryptTokenField / decryptTokenField with additional authenticated data (#293)", () => {
	const aad = "ft:sid-1:google";

	it("roundtrips when the same AAD is presented on decrypt", () => {
		const ct = encryptTokenField(plaintext, key, aad);
		expect(ct).not.toContain(plaintext);
		expect(decryptTokenField(ct, key, aad)).toBe(plaintext);
	});

	it("does not store the AAD in the envelope — the format is unchanged", () => {
		const ct = encryptTokenField(plaintext, key, aad);
		expect(ct.split(".")).toHaveLength(4);
		expect(ct).not.toContain(Buffer.from(aad).toString("base64url"));
	});

	it("fails authentication under a different AAD", () => {
		const ct = encryptTokenField(plaintext, key, aad);
		expect(() => decryptTokenField(ct, key, "ft:sid-2:google")).toThrow();
	});

	it("fails authentication when the AAD is omitted on decrypt", () => {
		const ct = encryptTokenField(plaintext, key, aad);
		expect(() => decryptTokenField(ct, key)).toThrow();
	});

	it("fails authentication when an AAD is presented for a ciphertext sealed without one", () => {
		const ct = encryptTokenField(plaintext, key);
		expect(() => decryptTokenField(ct, key, aad)).toThrow();
	});
});
