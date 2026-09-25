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

/**
 * The `v2` key-ring envelope a value is sealed in at rest:
 * `v2.<key id>.<iv>.<ciphertext>.<tag>`, each segment base64url, AES-256-GCM
 * under the ring's first key. The GCM additional authenticated data is
 *
 *     <purpose> NUL ‖ u32(len key id) ‖ key id ‖ u32(len record) ‖ record
 *
 * (lengths 32-bit big-endian): the caller's purpose label, the ID of the key
 * that sealed, and the bytes of the record the value belongs to. None of it
 * is stored but the key ID; the caller presents the same purpose and record
 * to open.
 *
 * The format is at rest in deployments. The federation grant store in
 * `@o3co/auth-provider-redis` has sealed under it with the purpose
 * `o3co:redis:v2` since before it moved here, which is why the header is a
 * NUL-terminated label rather than a length-prefixed one: that store's header
 * was always `o3co:redis:v2\0`.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { checkSealingKeyRing, isSealingKeyId, type SealingKeyRing } from "./keyRing.mjs";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const VERSION = "v2";

/**
 * What a sealed value is bound to besides its key. Both are authenticated
 * and neither is stored: a value presented under another purpose, or with
 * another record's bytes, does not open.
 */
export interface SealBinding {
	/**
	 * Names what is sealed, so that two callers sealing under one ring cannot
	 * read each other's values. One to 64 printable ASCII characters, no
	 * space: it is written followed by a NUL, so no purpose is a prefix of
	 * another's header. Fixed for as long as values sealed under it are at
	 * rest.
	 */
	readonly purpose: string;
	/**
	 * The record's own authenticated data: what binds a value to the record
	 * it belongs to, so that a value copied into another record does not
	 * open there.
	 */
	readonly record: Buffer;
}

/**
 * What opening an envelope can say. Not an exception, because two of the
 * three are ordinary answers a store hands to its caller: an operator who
 * dropped a key can put it back (`key_unavailable`), and a value whose
 * authenticated data no longer matches never opens again (`unreadable`).
 */
export type OpenedSeal =
	| { readonly state: "ok"; readonly value: string }
	| { readonly state: "unreadable" }
	| { readonly state: "key_unavailable" };

const PURPOSE_PATTERN = /^[\x21-\x7E]{1,64}$/;

const header = (purpose: string): Buffer => {
	if (!PURPOSE_PATTERN.test(purpose)) {
		throw new RangeError(
			"sealing purpose must be 1 to 64 printable ASCII characters, without a space",
		);
	}
	return Buffer.from(`${purpose}\0`, "ascii");
};

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

/** The GCM AAD: the purpose's header, then the key ID and the record, each length-prefixed so none can absorb another. */
const aad = (head: Buffer, keyId: Buffer, record: Buffer): Buffer =>
	Buffer.concat([head, u32(keyId.length), keyId, u32(record.length), record]);

/**
 * Seals under the ring's first key and returns
 * `v2.<key id>.<iv>.<ciphertext>.<tag>`, each segment base64url. The key ID
 * is encoded rather than written literally so that the separator cannot
 * appear inside it whatever an operator configures.
 *
 * Throws on a ring that could not seal (empty, or refused by
 * `checkSealingKeyRing`) and a purpose outside {@link SealBinding.purpose}'s
 * rule (`RangeError`): both are faults of the caller or its configuration,
 * never of the value.
 *
 * A wrong IV or tag length is not checked on open: `createDecipheriv` and
 * `setAuthTag` refuse both, and a check in front of them could only ever
 * report what they already do.
 */
export function sealWithKeyRing(
	plaintext: string,
	ring: SealingKeyRing,
	binding: SealBinding,
): string {
	checkSealingKeyRing(ring);
	const head = header(binding.purpose);
	const sealing = ring[0];
	if (sealing === undefined) throw new Error("no encryption key to seal with");
	const keyId = Buffer.from(sealing.id, "utf8");
	const iv = randomBytes(IV_LEN);
	const cipher = createCipheriv(ALGO, sealing.key, iv);
	cipher.setAAD(aad(head, keyId, binding.record));
	const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	return [
		VERSION,
		keyId.toString("base64url"),
		iv.toString("base64url"),
		ct.toString("base64url"),
		cipher.getAuthTag().toString("base64url"),
	].join(".");
}

/**
 * Inverse of {@link sealWithKeyRing}. The envelope is parsed whole before the
 * ring is consulted, so that a malformed one is never reported as a missing
 * key: `key_unavailable` says the operator can put a key back, and saying it
 * of a corrupted value would send them looking for a key that would not
 * help. No key is ever tried but the one the envelope names.
 *
 * Throws, as sealing does, on a malformed ring or purpose.
 */
export function openWithKeyRing(
	envelope: string,
	ring: SealingKeyRing,
	binding: SealBinding,
): OpenedSeal {
	checkSealingKeyRing(ring);
	const head = header(binding.purpose);
	const parts = envelope.split(".");
	if (parts.length !== 5 || parts[0] !== VERSION) return { state: "unreadable" };
	const keyId = canonical(parts[1] as string);
	const iv = canonical(parts[2] as string);
	const ct = canonical(parts[3] as string);
	const tag = canonical(parts[4] as string);
	if (keyId === undefined || iv === undefined || ct === undefined || tag === undefined) {
		return { state: "unreadable" };
	}
	const id = keyId.toString("utf8");
	if (!isSealingKeyId(id)) return { state: "unreadable" };
	const entry = ring.find((candidate) => candidate.id === id);
	if (entry === undefined) return { state: "key_unavailable" };
	try {
		const decipher = createDecipheriv(ALGO, entry.key, iv);
		decipher.setAAD(aad(head, keyId, binding.record));
		decipher.setAuthTag(tag);
		const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
		return { state: "ok", value: pt.toString("utf8") };
	} catch {
		return { state: "unreadable" };
	}
}
