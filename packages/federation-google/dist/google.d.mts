import { type FederationProvider, type SupportsClaimMapping, type SupportsLogout, type SupportsRefresh } from "@o3co/auth-provider-session";
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly googleFederationConfig?: GoogleProviderConfig;
    }
}
export interface GoogleProviderConfig {
    clientId: string;
    clientSecret: string;
    callbackURL: string;
    /** Cookie / session domain used to validate redirect URLs (e.g. ".example.com"). Optional. */
    sessionDomain?: string;
    /** URL of the auth-callback page (used to build the post-login redirect). Optional. */
    authCallbackUrl?: string;
    /** Fallback URL for the client app (used when no redirectTo is present). Optional. */
    clientUrl?: string;
    /** Override Google's end-session endpoint. When omitted, the provider redirects directly
     *  to postLogoutRedirectUri (or accounts.google.com/Logout as fallback). */
    endSessionEndpoint?: string;
}
export type GoogleProvider = FederationProvider & SupportsRefresh & SupportsLogout & SupportsClaimMapping;
export declare function createGoogleProvider(config: GoogleProviderConfig): GoogleProvider;
/**
 * Const Module for the Google federation integration.
 *
 * Contributes both `federations.google` (FederationProvider — upstream OIDC
 * protocol) and `federationRedirectPolicies.google` (FederationRedirectPolicy
 * — consumer redirect URL policy).
 *
 * Config supplied via the `googleFederationConfig` ComponentMap slot
 * (per A5 §10.1 const-Module pattern). v0.5.0 is single-tenant: the federation
 * is registered under name "google". Multi-tenant support deferred post-publish.
 *
 * Per A5 §10.1.
 */
export declare const googleFederationModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=google.d.mts.map