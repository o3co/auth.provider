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

/**
 * One key in the ring a federation grant's credential is sealed under
 * (#593, D16). The first entry seals; every entry may open.
 *
 * A ring, and not the one key the session-bound store takes, because a
 * mistake here revokes every user's delegation at once: an operator must be
 * able to introduce a key without re-sealing records that are paused, and to
 * put a key back that was dropped by accident.
 */
export interface FederationGrantKey {
	/** Named inside the envelope. One to 64 characters of `A-Za-z0-9_-`: the separator may not appear in it. */
	readonly id: string;
	readonly key: Buffer;
}

/**
 * What opening a sealed credential can say. Not an exception, because two of
 * the three are ordinary answers the store hands to a caller: an operator
 * who dropped a key can put it back (`key_unavailable`), and a record whose
 * authenticated data no longer matches never opens again (`unreadable`).
 */
export type OpenedCredential =
	| { readonly state: "ok"; readonly value: string }
	| { readonly state: "unreadable" }
	| { readonly state: "key_unavailable" };

const V2 = "v2";
const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
/** Names the format and binds the key ID, so that an envelope cannot be re-labelled to another key. */
const V2_HEADER = Buffer.from("o3co:redis:v2\0", "ascii");

const u32 = (value: number): Buffer => {
	if (!Number.isInteger(value) || value < 0 || value > 0xff_ff_ff_ff) {
		throw new Error("length exceeds a 32-bit prefix");
	}
	const out = Buffer.alloc(4);
	out.writeUInt32BE(value);
	return out;
};

/**
 * `Buffer.from(s, "base64url")` drops what it cannot decode instead of
 * refusing, so a segment that is not canonical base64url would be read as
 * some shorter value. Re-encoding is the check.
 */
const canonical = (segment: string): Buffer | undefined => {
	const bytes = Buffer.from(segment, "base64url");
	return bytes.toString("base64url") === segment ? bytes : undefined;
};

const checkRing = (ring: readonly FederationGrantKey[]): void => {
	const seen = new Set<string>();
	for (const entry of ring) {
		if (!KEY_ID_PATTERN.test(entry.id)) {
			throw new Error(`federation grant encryption key id must match ${KEY_ID_PATTERN.source}`);
		}
		if (seen.has(entry.id)) throw new Error(`duplicate federation grant encryption key id`);
		seen.add(entry.id);
		if (entry.key.length !== KEY_LEN) throw new Error(`encryption key must be ${KEY_LEN} bytes`);
	}
};

/** The GCM AAD: the header, the key ID and the record's own data, each length-prefixed so none can absorb another. */
const v2Aad = (keyId: Buffer, record: Buffer): Buffer =>
	Buffer.concat([V2_HEADER, u32(keyId.length), keyId, u32(record.length), record]);

/**
 * Seals under the ring's first key and returns
 * `v2.<key id>.<iv>.<ciphertext>.<tag>`, each segment base64url. The key ID
 * is encoded rather than written literally so that the separator cannot
 * appear inside it whatever an operator configures.
 *
 * `record` is authenticated and not stored: the caller presents the same
 * bytes to open, which is what binds a credential to the record that
 * authorizes it (D16).
 *
 * A wrong IV or tag length is not checked here: `createDecipheriv` and
 * `setAuthTag` refuse both, and a check in front of them could only ever
 * report what they already do.
 */
export function sealCredential(
	plaintext: string,
	ring: readonly FederationGrantKey[],
	record: Buffer,
): string {
	checkRing(ring);
	const sealing = ring[0];
	if (sealing === undefined) throw new Error("no federation grant encryption key to seal with");
	const keyId = Buffer.from(sealing.id, "utf8");
	const iv = randomBytes(IV_LEN);
	const cipher = createCipheriv(ALGO, sealing.key, iv);
	cipher.setAAD(v2Aad(keyId, record));
	const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	return [
		V2,
		keyId.toString("base64url"),
		iv.toString("base64url"),
		ct.toString("base64url"),
		cipher.getAuthTag().toString("base64url"),
	].join(".");
}

/**
 * Inverse of {@link sealCredential}. The envelope is parsed whole before the
 * ring is consulted, so that a malformed one is never reported as a missing
 * key: `key_unavailable` says the operator can put a key back, and saying it
 * of a corrupted record would send them looking for a key that would not
 * help. No key is ever tried but the one the envelope names.
 */
export function openSealedCredential(
	envelope: string,
	ring: readonly FederationGrantKey[],
	record: Buffer,
): OpenedCredential {
	checkRing(ring);
	const parts = envelope.split(".");
	if (parts.length !== 5 || parts[0] !== V2) return { state: "unreadable" };
	const keyId = canonical(parts[1] as string);
	const iv = canonical(parts[2] as string);
	const ct = canonical(parts[3] as string);
	const tag = canonical(parts[4] as string);
	if (keyId === undefined || iv === undefined || ct === undefined || tag === undefined) {
		return { state: "unreadable" };
	}
	const id = keyId.toString("utf8");
	if (!KEY_ID_PATTERN.test(id)) return { state: "unreadable" };
	const entry = ring.find((candidate) => candidate.id === id);
	if (entry === undefined) return { state: "key_unavailable" };
	try {
		const decipher = createDecipheriv(ALGO, entry.key, iv);
		decipher.setAAD(v2Aad(keyId, record));
		decipher.setAuthTag(tag);
		const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
		return { state: "ok", value: pt.toString("utf8") };
	} catch {
		return { state: "unreadable" };
	}
}
