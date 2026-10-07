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
import { checkSealingKeyRing, isSealingKeyId } from "./keyRing.mjs";
const ALGO = "aes-256-gcm";
const IV_LEN = 12;
/**
 * The only tag length sealed and the only one read. Node before 26 accepts
 * a GCM tag of 4 to 16 bytes on decrypt unless the decipher is told the
 * length, and a short tag is both easier to forge and a way to recover the
 * authentication key.
 */
const TAG_LEN = 16;
const VERSION = "v2";
const PURPOSE_PATTERN = /^[\x21-\x7E]{1,64}$/;
/**
 * What a ring handed straight to seal or open is called in a refusal. A
 * reader that took the ring from its configuration checks it first with
 * `checkSealingKeyRing`, under the key it read it from.
 */
const RING_SETTING = "sealing key ring";
const header = (purpose) => {
    // A string first: `test` and the template literal below both coerce, so a
    // JS caller's `undefined` would otherwise seal under the label "undefined".
    if (typeof purpose !== "string" || !PURPOSE_PATTERN.test(purpose)) {
        throw new RangeError("sealing purpose must be 1 to 64 printable ASCII characters, without a space");
    }
    return Buffer.from(`${purpose}\0`, "ascii");
};
const u32 = (value) => {
    if (!Number.isInteger(value) || value < 0 || value > 0xff_ff_ff_ff) {
        throw new RangeError("sealing record is longer than a 32-bit length prefix can state");
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
const canonical = (segment) => {
    const bytes = Buffer.from(segment, "base64url");
    return bytes.toString("base64url") === segment ? bytes : undefined;
};
/** The GCM AAD: the purpose's header, then the key ID and the record, each length-prefixed so none can absorb another. */
const aad = (head, keyId, record) => Buffer.concat([head, u32(keyId.length), keyId, u32(record.length), record]);
/**
 * Seals under the ring's first key and returns
 * `v2.<key id>.<iv>.<ciphertext>.<tag>`, each segment base64url. The key ID
 * is encoded rather than written literally so that the separator cannot
 * appear inside it whatever an operator configures.
 *
 * Throws a `RangeError` on a ring that could not seal (empty, or refused by
 * `checkSealingKeyRing`, under the name "sealing key ring"), on a purpose
 * outside {@link SealBinding.purpose}'s rule, and on a record longer than a
 * 32-bit length prefix can state: each a fault of the caller or its
 * configuration, never of the value.
 */
export function sealWithKeyRing(plaintext, ring, binding) {
    checkSealingKeyRing(ring, RING_SETTING);
    const head = header(binding.purpose);
    const sealing = ring[0];
    if (sealing === undefined) {
        throw new RangeError(`${RING_SETTING} has no encryption key to seal with`);
    }
    const keyId = Buffer.from(sealing.id, "utf8");
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv(ALGO, sealing.key, iv, { authTagLength: TAG_LEN });
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
 * Throws a `RangeError`, as sealing does, on a malformed ring or purpose.
 */
export function openWithKeyRing(envelope, ring, binding) {
    checkSealingKeyRing(ring, RING_SETTING);
    const head = header(binding.purpose);
    const parts = envelope.split(".");
    if (parts.length !== 5 || parts[0] !== VERSION)
        return { state: "unreadable" };
    const keyId = canonical(parts[1]);
    const iv = canonical(parts[2]);
    const ct = canonical(parts[3]);
    const tag = canonical(parts[4]);
    if (keyId === undefined || iv === undefined || ct === undefined || tag === undefined) {
        return { state: "unreadable" };
    }
    // Every envelope is sealed with a 12-byte IV and a 16-byte tag; GCM itself
    // would take other lengths, and a shorter tag is a weaker one.
    if (iv.length !== IV_LEN || tag.length !== TAG_LEN)
        return { state: "unreadable" };
    const id = keyId.toString("utf8");
    if (!isSealingKeyId(id))
        return { state: "unreadable" };
    const entry = ring.find((candidate) => candidate.id === id);
    if (entry === undefined)
        return { state: "key_unavailable", keyId: id };
    try {
        const decipher = createDecipheriv(ALGO, entry.key, iv, { authTagLength: TAG_LEN });
        decipher.setAAD(aad(head, keyId, binding.record));
        decipher.setAuthTag(tag);
        const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
        return { state: "ok", value: pt.toString("utf8"), keyId: id };
    }
    catch {
        return { state: "unreadable" };
    }
}
