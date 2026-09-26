import type { ExtractedKey } from "../resolver/extractKey.mjs";
/**
 * Extract raw Ed25519 public key bytes from a resolved key.
 *
 * - JWK format: the `x` field is base64url-encoded raw 32-byte key.
 * - Multibase format: base58btc string (prefixed with 'z'), multicodec-prefixed (0xed 0x01).
 */
export declare function extractEd25519PublicKeyBytes(resolvedKey: ExtractedKey): Uint8Array;
//# sourceMappingURL=ed25519Utils.d.mts.map