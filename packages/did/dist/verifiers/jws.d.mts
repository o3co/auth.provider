import type { SignatureVerifier, VerificationContext, VerificationResult } from "./types.mjs";
type JwsAlgorithm = "EdDSA" | "ES256" | "ES256K";
export declare class JwsVerifier implements SignatureVerifier {
    private readonly expectedAlg;
    constructor(expectedAlg: JwsAlgorithm);
    verify(ctx: VerificationContext): Promise<VerificationResult>;
}
export {};
//# sourceMappingURL=jws.d.mts.map