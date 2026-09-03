import { type GrantDependencies, type GrantHandler } from "@o3co/auth-provider-core";
import type { DidDocumentResolver } from "./resolver/types.mjs";
import type { VerifierRegistry } from "./verifiers/registry.mjs";
export interface DidGrantOptions {
    resolver: DidDocumentResolver;
    verifierRegistry?: VerifierRegistry;
}
export declare const createDidGrant: (deps: GrantDependencies, options: DidGrantOptions) => GrantHandler;
//# sourceMappingURL=did.d.mts.map