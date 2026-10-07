import type { FederationProvider, SupportsClaimMapping, SupportsLogout, SupportsRefresh } from "./types.mjs";
export interface GoogleProviderConfig {
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
    /** Override Google's end-session endpoint. When omitted, the provider redirects directly
     *  to postLogoutRedirectUri (or accounts.google.com/Logout as fallback). */
    endSessionEndpoint?: string;
}
type GoogleProvider = FederationProvider & SupportsRefresh & SupportsLogout & SupportsClaimMapping;
export declare function createGoogleProvider(config: GoogleProviderConfig): GoogleProvider;
export {};
//# sourceMappingURL=google.d.mts.map