/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { createCipheriv } from "node:crypto";
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

// Node before 26 accepts a GCM tag of 4 to 16 bytes on decrypt unless told
// the length, so a v1 envelope whose tag was cut short decrypted. Every v1
// envelope ever written has a 12-byte IV and a 16-byte tag.
describe("decryptTokenField reads only a 16-byte tag and a 12-byte IV", () => {
	const aad = "ft:sid-1:google";

	it("refuses a tag cut to 4, 8 or 12 bytes as a malformed envelope", () => {
		const [ver, iv, ct, tag] = encryptTokenField(plaintext, key, aad).split(".") as [
			string,
			string,
			string,
			string,
		];
		for (const length of [4, 8, 12]) {
			const truncated = Buffer.from(tag, "base64url").subarray(0, length).toString("base64url");
			expect(
				() => decryptTokenField([ver, iv, ct, truncated].join("."), key, aad),
				`a ${length}-byte tag`,
			).toThrow(new Error("invalid envelope format"));
		}
	});

	it("refuses a 16-byte IV, even one sealed under the right key and AAD", () => {
		const iv = Buffer.alloc(16, 9);
		const cipher = createCipheriv("aes-256-gcm", key, iv);
		cipher.setAAD(Buffer.from(aad, "utf8"));
		const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
		const envelope = [
			"v1",
			iv.toString("base64url"),
			ct.toString("base64url"),
			cipher.getAuthTag().toString("base64url"),
		].join(".");
		expect(() => decryptTokenField(envelope, key, aad)).toThrow(
			new Error("invalid envelope format"),
		);
	});

	it("names no stored bytes when the version is not its own", () => {
		// The first segment is whatever was stored. The token store drops this
		// refusal without logging it today, so the fixed text is defence in
		// depth: a caller that logs the error later must find no stored bytes.
		const sealed = encryptTokenField(plaintext, key, aad);
		const stored = sealed.replace(/^v1\./, "ya29-a-stored-token-fragment.");
		expect(() => decryptTokenField(stored, key, aad)).toThrow(
			new Error("unsupported envelope version"),
		);
	});
});
