import type { PathResolver } from "@o3co/auth-provider-core";
import type { SignatureVerifier } from "./types.mjs";
export type VerifierFactory = (pathResolver?: PathResolver) => Promise<SignatureVerifier>;
export declare class VerifierRegistry {
    private factories;
    register(algorithm: string, factory: VerifierFactory): void;
    get(algorithm: string): VerifierFactory | undefined;
    has(algorithm: string): boolean;
    algorithms(): string[];
}
//# sourceMappingURL=registry.d.mts.map