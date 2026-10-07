import { type FederationClientSecret, type FederationProvider, type SupportsClaimMapping, type SupportsLogout, type SupportsRefresh } from "@o3co/auth-provider-session";
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly appleFederationConfig?: AppleProviderConfig;
    }
}
export declare const APPLE_ISSUER = "https://appleid.apple.com";
/** The domain of a Hide My Email relay address. */
export declare const APPLE_PRIVATE_RELAY_DOMAIN = "privaterelay.appleid.com";
/**
 * Whether an address is an Apple Hide My Email relay.
 *
 * Exact-domain match, case-insensitive. A suffix test would accept
 * `privaterelay.appleid.com.attacker.example`, which is a domain an attacker
 * can register.
 */
export declare function isPrivateRelayEmail(email: string): boolean;
export interface AppleProviderConfig {
    /**
     * The **Services ID** (e.g. `com.example.app.service`), not the App ID.
     * Apple treats a web OAuth client as a Services ID configured under an App
     * ID; the bundle identifier itself is never the `client_id` here.
     */
    clientId: string;
    /**
     * Return URL registered against the Services ID.
     *
     * Two separate rules, both checked at construction rather than discovered
     * as an opaque `invalid_request` at the authorization endpoint: the scheme
     * must be `https`, **and** the host must not be loopback — Apple rejects
     * `localhost`, `127.0.0.0/8` and `[::1]` even over `https`, so local
     * development needs a tunnel or a dev hostname holding a certificate.
     */
    callbackURL: string;
    /**
     * The client secret, either already-computed or a resolver. Supply this
     * **or** `teamId` + `keyId` + `privateKey`, never both.
     *
     * Apple's secret is an ES256 JWT capped at six months, so the practical
     * form is a resolver — `createAppleClientSecret(...)`, which this module
     * builds for you when you hand it the key material instead.
     */
    clientSecret?: FederationClientSecret;
    /** Apple Developer Team ID. With `keyId` + `privateKey`, builds the signer. */
    teamId?: string;
    /** Key ID of the downloaded `.p8`. */
    keyId?: string;
    /** The `.p8` private key, PKCS#8 PEM. */
    privateKey?: string;
    /**
     * Exact URLs a consumer-supplied `redirect_to` may name. Absent or empty
     * means no `redirect_to` is accepted at all — see `createFederationRedirectPolicy`.
     */
    redirectAllowlist?: readonly string[];
    /** Cookie / session domain; every non-loopback `redirectAllowlist` entry must be inside it. Optional. */
    sessionDomain?: string;
    /** URL of the auth-callback page (used to build the post-login redirect). Optional. */
    authCallbackUrl?: string;
    /** Fallback URL for the client app (used when no redirectTo is present). Optional. */
    clientUrl?: string;
    /**
     * Upstream logout endpoint. Apple publishes no `end_session_endpoint`, so
     * absent this the provider can only redirect to `postLogoutRedirectUri`.
     */
    endSessionEndpoint?: string;
    /** Override Apple's JWKS URI. Default: `https://appleid.apple.com/auth/keys`.
     *  Test injection only — production deployments rely on the default. */
    jwksUri?: string;
}
export type AppleProvider = FederationProvider & SupportsRefresh & SupportsLogout & SupportsClaimMapping;
export declare function createAppleProvider(config: AppleProviderConfig): AppleProvider;
/**
 * Const Module for the Sign in with Apple federation integration.
 *
 * Contributes both `federations.apple` (FederationProvider — upstream OIDC
 * protocol) and `federationRedirectPolicies.apple` (FederationRedirectPolicy
 * — consumer redirect URL policy), the pairing A5 §6 requires.
 *
 * Config arrives through the `appleFederationConfig` ComponentMap slot (per
 * A5 §10.1 const-Module pattern). Single-tenant, as the Google and GitHub
 * modules are: the federation is registered under the name "apple".
 */
export declare const appleFederationModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=apple.d.mts.map