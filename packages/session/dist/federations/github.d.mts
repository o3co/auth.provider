import type { FederationProvider, SupportsClaimMapping, SupportsLogout } from "./types.mjs";
export interface GithubProviderConfig {
    /** Strategy identifier — use a unique name per tenant for multi-tenant setups. */
    name: string;
    clientId: string;
    clientSecret: string;
    callbackURL: string;
    /** Cookie / session domain used to validate redirect URLs (e.g. ".example.com"). Optional. */
    sessionDomain?: string;
    /** URL of the auth-callback page (used to build the post-login redirect). Optional. */
    authCallbackUrl?: string;
    /** Fallback URL for the client app (used when no redirectTo is present). Optional. */
    clientUrl?: string;
    /** Override GitHub's end-session endpoint. When omitted, the provider redirects directly
     *  to postLogoutRedirectUri. */
    endSessionEndpoint?: string;
}
type GithubProvider = FederationProvider & SupportsLogout & SupportsClaimMapping;
export declare function createGithubProvider(config: GithubProviderConfig): GithubProvider;
export {};
//# sourceMappingURL=github.d.mts.map