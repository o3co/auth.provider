import type { PathResolver } from "@o3co/auth-provider-core";
import { type VerifierFactory, VerifierRegistry } from "./registry.mjs";
import type { SignatureVerifier } from "./types.mjs";
export type Algorithm = string;
export declare function createDefaultVerifierRegistry(): VerifierRegistry;
export declare function createVerifier(algorithm: Algorithm, pathResolver?: PathResolver): Promise<SignatureVerifier>;
export type { VerifierFactory };
//# sourceMappingURL=factory.d.mts.map