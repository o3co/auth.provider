/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Sealing at rest for the Redis stores. The session-bound federation-token
 * store's `v1` envelope (one key, `v1.<iv>.<ciphertext>.<tag>`) is here. The
 * federation grant store seals in core's `v2` key-ring envelope (the
 * `sealing/` leaf of `@o3co/auth-provider-core`); what is here of it is the
 * store's purpose label and the names the store has always called it by.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
	type OpenedSeal,
	openWithKeyRing,
	type SealingKey,
	sealWithKeyRing,
} from "@o3co/auth-provider-core";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
/**
 * The only tag length written and the only one read: Node before 26 accepts
 * a GCM tag of 4 to 16 bytes on decrypt unless told the length.
 */
const TAG_LEN = 16;
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
	const cipher = createCipheriv(ALGO, key, iv, { authTagLength: TAG_LEN });
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
	// The segment is stored text, not ours to quote, whoever logs this later.
	if (ver !== VERSION) throw new Error("unsupported envelope version");
	const iv = Buffer.from(ivB64, "base64url");
	const ct = Buffer.from(ctB64, "base64url");
	const tag = Buffer.from(tagB64, "base64url");
	// Every v1 envelope is written with a 12-byte IV and a 16-byte tag; GCM
	// itself would take other lengths, and a shorter tag is a weaker one.
	if (iv.length !== IV_LEN || tag.length !== TAG_LEN) throw new Error("invalid envelope format");
	const decipher = createDecipheriv(ALGO, key, iv, { authTagLength: TAG_LEN });
	if (aad !== undefined) decipher.setAAD(aadBytes(aad));
	decipher.setAuthTag(tag);
	const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
	return pt.toString("utf8");
}

/**
 * One key in the ring a federation grant's credential is sealed under
 * (#593, D16): core's {@link SealingKey}, under the name this package has
 * always exported it by. The first entry seals; every entry may open.
 */
export type FederationGrantKey = SealingKey;

/**
 * The purpose every federation grant credential has been sealed under. The
 * envelope writes it into the authenticated data as `o3co:redis:v2\0`, the
 * header this store used before the envelope moved to core; changing it
 * leaves every grant at rest unreadable.
 */
const FEDERATION_GRANT_PURPOSE = "o3co:redis:v2";

/**
 * Seals a federation grant's credential in core's `v2` key-ring envelope
 * (`v2.<key id>.<iv>.<ciphertext>.<tag>`) under the ring's first key.
 *
 * `record` is authenticated and not stored: the caller presents the same
 * bytes to open, which is what binds a credential to the record that
 * authorizes it (D16).
 */
export function sealCredential(
	plaintext: string,
	ring: readonly FederationGrantKey[],
	record: Buffer,
): string {
	return sealWithKeyRing(plaintext, ring, { purpose: FEDERATION_GRANT_PURPOSE, record });
}

/** Inverse of {@link sealCredential}; see core's `openWithKeyRing` for what each state means. */
export function openSealedCredential(
	envelope: string,
	ring: readonly FederationGrantKey[],
	record: Buffer,
): OpenedSeal {
	return openWithKeyRing(envelope, ring, { purpose: FEDERATION_GRANT_PURPOSE, record });
}
