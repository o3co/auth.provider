/**
 * The key ring a value is sealed under at rest: what one key is, what a ring
 * of them must satisfy, and how a configured key becomes key material. The
 * envelope that uses the ring is `envelope.mts`.
 */
/** AES-256: every key in a ring is exactly this many bytes. */
export declare const SEALING_KEY_BYTES = 32;
/**
 * One key in a sealing key ring. The ring's first entry seals; every entry
 * may open.
 *
 * A ring, and not one key, because a mistake with the key revokes every value
 * sealed under it at once: an operator must be able to introduce a key
 * without re-sealing values at rest, and to put back a key that was dropped by
 * accident.
 */
export interface SealingKey {
    /** Named inside the envelope. One to 64 characters of `A-Za-z0-9_-`: the separator may not appear in it. */
    readonly id: string;
    /** {@link SEALING_KEY_BYTES} bytes. */
    readonly key: Buffer;
}
/** The keys a value is sealed and opened under, in order: the first seals. */
export type SealingKeyRing = readonly SealingKey[];
/**
 * Whether `id` is one a ring may hold, and so one an envelope may name: a
 * string of 1 to 64 characters of `A-Za-z0-9_-`. Anything but a string is
 * not, whatever its text would be.
 */
export declare const isSealingKeyId: (id: unknown) => id is string;
/**
 * Refuses, as a `RangeError`, a ring no envelope could be sealed or opened
 * under: a key ID outside the rule, a duplicate ID, or a key that is not a
 * Buffer of {@link SEALING_KEY_BYTES} bytes (a string of that length would be
 * used as its UTF-8 bytes). A ring is a setting, and one that is given but
 * unusable is refused rather than worked around. An empty ring passes;
 * whether one may be empty is the caller's to say (it can open nothing and
 * seal nothing).
 *
 * `setting` names the ring in the refusal, as its reader knows it: the
 * configuration key it was read from (`federationGrants.encryptionKeys`), or the option
 * it was passed as. Every refusal names the entry by its index and none
 * quotes an ID: an operator who swapped an ID and its key would otherwise
 * see the key in a boot error, and passing the ID rule does not make an ID
 * safe to quote (a 32-byte key in hex, or in unpadded base64url, passes).
 */
export declare function checkSealingKeyRing(ring: SealingKeyRing, setting: string): void;
/**
 * A configured key as key material: canonical base64 of exactly
 * {@link SEALING_KEY_BYTES} bytes, or `undefined`. The caller refuses the
 * `undefined`, naming the configuration key it read.
 *
 * `Buffer.from(…, "base64")` ignores embedded whitespace and drops what it
 * cannot decode, so a value is read only if re-encoding gives it back
 * exactly: a key pasted out of a file with its newline, or wrapped by a
 * secret manager, is not the value an operator checked.
 */
export declare function decodeSealingKey(encoded: string): Buffer | undefined;
//# sourceMappingURL=keyRing.d.mts.map