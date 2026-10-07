import type { PathResolver } from "@o3co/auth-provider-core";
import type { SignatureVerifier, VerificationContext, VerificationResult } from "./types.mjs";
export declare class Ed25519RawVerifier implements SignatureVerifier {
    private verifyAsync;
    private pathResolver;
    constructor(pathResolver?: PathResolver);
    private loadVerifyAsync;
    verify(ctx: VerificationContext): Promise<VerificationResult>;
}
//# sourceMappingURL=ed25519Raw.d.mts.map