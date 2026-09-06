import { type FederationProvider, type SupportsClaimMapping, type SupportsLogout } from "@o3co/auth-provider-session";
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly githubFederationConfig?: GithubProviderConfig;
    }
}
export interface GithubProviderConfig {
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
export type GithubProvider = FederationProvider & SupportsLogout & SupportsClaimMapping;
export declare function createGithubProvider(config: GithubProviderConfig): GithubProvider;
/**
 * Const Module for the GitHub federation integration.
 *
 * Contributes both `federations.github` (FederationProvider — upstream OAuth 2
 * protocol) and `federationRedirectPolicies.github` (FederationRedirectPolicy
 * — consumer redirect URL policy).
 *
 * Config supplied via the `githubFederationConfig` ComponentMap slot
 * (per A5 §10.2 const-Module pattern).
 *
 * Per A5 §10.2.
 */
export declare const githubFederationModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=github.d.mts.map