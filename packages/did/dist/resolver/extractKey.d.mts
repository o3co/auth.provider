import type { DidDocument, JsonWebKey } from "./types.mjs";
export type ExtractedKey = {
    format: "jwk";
    key: JsonWebKey;
} | {
    format: "multibase";
    key: string;
};
/**
 * Extract a verification key from a DID Document for the given DID.
 *
 * Matching logic: find a verificationMethod whose `controller` equals the DID,
 * or whose `id` starts with `${did}#`.
 *
 * @throws if no verificationMethod array is present, no matching method is found,
 *         or the matching method has no key material.
 */
export declare function extractVerificationKey(doc: DidDocument, did: string): Promise<ExtractedKey>;
//# sourceMappingURL=extractKey.d.mts.map