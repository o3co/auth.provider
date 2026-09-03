/**
 * Extract a verification key from a DID Document for the given DID.
 *
 * Matching logic: find a verificationMethod whose `controller` equals the DID,
 * or whose `id` starts with `${did}#`.
 *
 * @throws if no verificationMethod array is present, no matching method is found,
 *         or the matching method has no key material.
 */
export async function extractVerificationKey(doc, did) {
    if (!doc.verificationMethod || doc.verificationMethod.length === 0) {
        throw new Error(`DID Document for ${did} has no verificationMethod`);
    }
    const method = doc.verificationMethod.find((vm) => vm.controller === did || vm.id.startsWith(`${did}#`));
    if (!method) {
        throw new Error(`No verificationMethod found for DID ${did}`);
    }
    if (method.publicKeyJwk !== undefined) {
        return { format: "jwk", key: method.publicKeyJwk };
    }
    if (method.publicKeyMultibase !== undefined) {
        return { format: "multibase", key: method.publicKeyMultibase };
    }
    throw new Error(`verificationMethod ${method.id} has no key material (publicKeyJwk or publicKeyMultibase)`);
}
