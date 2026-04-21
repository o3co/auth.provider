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
 * Encrypts a string and returns `${version}.${iv}.${ct}.${tag}` where each
 * component is base64url-encoded. Version is included so that future algorithm
 * migrations can be detected on decrypt.
 */
export function encryptTokenField(plaintext: string, key: Buffer): string {
	if (key.length !== KEY_LEN) throw new Error(`encryption key must be ${KEY_LEN} bytes`);
	const iv = randomBytes(IV_LEN);
	const cipher = createCipheriv(ALGO, key, iv);
	const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return [VERSION, iv.toString("base64url"), ct.toString("base64url"), tag.toString("base64url")].join(".");
}

export function decryptTokenField(envelope: string, key: Buffer): string {
	if (key.length !== KEY_LEN) throw new Error(`encryption key must be ${KEY_LEN} bytes`);
	const parts = envelope.split(".");
	if (parts.length !== 4) throw new Error("invalid envelope format");
	const [ver, ivB64, ctB64, tagB64] = parts;
	if (ver !== VERSION) throw new Error(`unsupported envelope version: ${ver}`);
	const iv = Buffer.from(ivB64!, "base64url");
	const ct = Buffer.from(ctB64!, "base64url");
	const tag = Buffer.from(tagB64!, "base64url");
	const decipher = createDecipheriv(ALGO, key, iv);
	decipher.setAuthTag(tag);
	const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
	return pt.toString("utf8");
}
