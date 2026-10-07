export { createDidGrant, type DidGrantOptions } from "./did.mjs";
export { type DidModuleOptions, didConfigSchema, oauthDidModule } from "./module.mjs";
export { type ExtractedKey, extractVerificationKey } from "./resolver/extractKey.mjs";
export type { DidDocument, DidDocumentResolver, VerificationMethod } from "./resolver/types.mjs";
export { detectAlgorithm } from "./verifiers/detect.mjs";
export { extractEd25519PublicKeyBytes } from "./verifiers/ed25519Utils.mjs";
export { type Algorithm, createDefaultVerifierRegistry, createVerifier, type VerifierFactory, } from "./verifiers/factory.mjs";
export { VerifierRegistry } from "./verifiers/registry.mjs";
export type { ParsedMessage, SignatureVerifier, VerificationContext, VerificationResult, } from "./verifiers/types.mjs";
//# sourceMappingURL=index.d.mts.map