/**
 * Client authentication for the exchange: the client `/oauth/token` authenticated,
 * or, on a route without it, the body's credentials. A public client and one whose
 * registration does not name this grant type are refused; a repository that cannot
 * answer is a `503`, never a verdict on the client.
 */
import { type GrantContext, type GrantDependencies, type GrantHandlerResult, type ProviderDeps, type PublicClient } from "@o3co/auth-provider-core";
import type { TokenRequest } from "./tokenRequest.mjs";
export declare function authenticateClient(deps: Pick<GrantDependencies, "logger">, clientRepository: ProviderDeps<"clientRepository">["clientRepository"], ctx: GrantContext, { bodyClientId, clientId, clientSecret, }: Pick<TokenRequest, "bodyClientId" | "clientId" | "clientSecret">): Promise<{
    readonly client: PublicClient;
} | GrantHandlerResult>;
//# sourceMappingURL=clientAuthentication.d.mts.map