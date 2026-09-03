/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const KEY_LEN = 32;
const VERSION = "v1";

/**
 * Additional authenticated data, as the callers hold it. A string is taken as
 * UTF-8; a Buffer is used as-is.
 */
export type Aad = string | Buffer;

const aadBytes = (aad: Aad): Buffer => (typeof aad === "string" ? Buffer.from(aad, "utf8") : aad);

/**
 * Encrypts a string and returns `${version}.${iv}.${ct}.${tag}` where each
 * component is base64url-encoded. Version is included so that future algorithm
 * migrations can be detected on decrypt.
 *
 * `aad` is authenticated but not stored: the same value must be presented on
 * decrypt, and a ciphertext presented under a different one (or under none)
 * fails the tag check, so the caller can bind a ciphertext to where it is
 * kept. The federation-token store passes the Redis key here (#293), which
 * is what makes a value copied to another session's key fail to decrypt
 * instead of quietly reading as that session's tokens. The wire format is
 * unchanged whether or not `aad` is given.
 */
export function encryptTokenField(plaintext: string, key: Buffer, aad?: Aad): string {
	if (key.length !== KEY_LEN) throw new Error(`encryption key must be ${KEY_LEN} bytes`);
	const iv = randomBytes(IV_LEN);
	const cipher = createCipheriv(ALGO, key, iv);
	if (aad !== undefined) cipher.setAAD(aadBytes(aad));
	const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return [
		VERSION,
		iv.toString("base64url"),
		ct.toString("base64url"),
		tag.toString("base64url"),
	].join(".");
}

/**
 * Inverse of {@link encryptTokenField}. `aad` must be exactly what was given
 * on encrypt (or omitted, if it was omitted then); anything else throws.
 */
export function decryptTokenField(envelope: string, key: Buffer, aad?: Aad): string {
	if (key.length !== KEY_LEN) throw new Error(`encryption key must be ${KEY_LEN} bytes`);
	const parts = envelope.split(".");
	if (parts.length !== 4) throw new Error("invalid envelope format");
	const ver = parts[0];
	const ivB64 = parts[1];
	const ctB64 = parts[2];
	const tagB64 = parts[3];
	if (ver === undefined || ivB64 === undefined || ctB64 === undefined || tagB64 === undefined) {
		throw new Error("invalid envelope format");
	}
	if (ver !== VERSION) throw new Error(`unsupported envelope version: ${ver}`);
	const iv = Buffer.from(ivB64, "base64url");
	const ct = Buffer.from(ctB64, "base64url");
	const tag = Buffer.from(tagB64, "base64url");
	const decipher = createDecipheriv(ALGO, key, iv);
	if (aad !== undefined) decipher.setAAD(aadBytes(aad));
	decipher.setAuthTag(tag);
	const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
	return pt.toString("utf8");
}
