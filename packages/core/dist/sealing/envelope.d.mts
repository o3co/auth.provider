import { type SealingKeyRing } from "./keyRing.mjs";
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
 *
 * `keyId` is the key the envelope names, which has passed the key id rule:
 * on `ok` the key that opened the value, so a caller can re-seal a value
 * opened under a key that is no longer first; on `key_unavailable` the key
 * to put back.
 */
export type OpenedSeal = {
    readonly state: "ok";
    readonly value: string;
    readonly keyId: string;
} | {
    readonly state: "unreadable";
} | {
    readonly state: "key_unavailable";
    readonly keyId: string;
};
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
export declare function sealWithKeyRing(plaintext: string, ring: SealingKeyRing, binding: SealBinding): string;
/**
 * Inverse of {@link sealWithKeyRing}. The envelope is parsed whole before the
 * ring is consulted, so that a malformed one is never reported as a missing
 * key: `key_unavailable` says the operator can put a key back, and saying it
 * of a corrupted value would send them looking for a key that would not
 * help. No key is ever tried but the one the envelope names.
 *
 * Throws a `RangeError`, as sealing does, on a malformed ring or purpose.
 */
export declare function openWithKeyRing(envelope: string, ring: SealingKeyRing, binding: SealBinding): OpenedSeal;
//# sourceMappingURL=envelope.d.mts.map