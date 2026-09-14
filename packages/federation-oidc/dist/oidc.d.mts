import { type FederationClientSecret, type FederationProvider, type SupportsClaimMapping, type SupportsLogout, type SupportsRefresh } from "@o3co/auth-provider-session";
import { type OidcPrivateKey } from "./client-auth.mjs";
/**
 * A generic OpenID Connect federation provider (#524): any OIDC-compliant
 * IdP — Okta, Entra ID, Auth0, Keycloak, a customer's own tenant — from
 * configuration alone, and as many instances as a deployment has issuers.
 *
 * ## What one instance does
 *
 * - **At construction** (boot): resolves the issuer's metadata through
 *   OpenID Connect Discovery. A discovery failure is fatal — there is no
 *   silent fallback to hand-typed endpoints; a deployment that wants those
 *   sets `discovery = false` and writes them down under `endpoints`.
 * - **Authorization request**: `authorization_code` with PKCE S256, `state`
 *   and `nonce`, all three minted by the session routes per transaction.
 * - **Callback**: exchanges the code with `client_secret_basic` or
 *   `private_key_jwt`, then validates the id_token — signature against the
 *   issuer's JWKS (cached, refetched on an unknown `kid`), `iss`, `aud`,
 *   `exp`, `iat`, `nonce`, and `at_hash` when present. UserInfo, when the
 *   issuer publishes it, is bound to the id_token's `sub`.
 * - **Identity**: `sub` is opaque and stable per issuer; the session routes
 *   hand `<name>:<sub>` to the Store, and an identity the Store does not
 *   know is refused — this package provisions nothing.
 */
export declare const DEFAULT_OIDC_SCOPES: readonly ["openid", "profile", "email"];
export interface OidcEndpointOverrides {
    readonly authorizationEndpoint?: string;
    readonly tokenEndpoint?: string;
    readonly jwksUri?: string;
    readonly userinfoEndpoint?: string;
    readonly endSessionEndpoint?: string;
}
export interface OidcProviderConfig {
    /** Issuer identifier, exactly as the IdP writes it into `iss`. https, or http on loopback. */
    readonly issuer: string;
    readonly clientId: string;
    /** `client_secret_basic`. A resolver is consulted per token request. */
    readonly clientSecret?: FederationClientSecret;
    /** `private_key_jwt`. A PEM PKCS#8 key, or `{ pem, kid?, alg? }`. */
    readonly privateKey?: string | OidcPrivateKey;
    /** Where the IdP sends the browser back; the session routes read it from `federations.<name>`. */
    readonly callbackURL: string;
    /** Default `openid profile email`; `openid` is mandatory. */
    readonly scopes?: readonly string[];
    /** Default true. When false, `endpoints` must name authorization, token and JWKS. */
    readonly discovery?: boolean;
    /** Overrides applied on top of (or instead of) the discovered metadata. */
    readonly endpoints?: OidcEndpointOverrides;
    /** Pin the id_token JWS algorithm; otherwise the issuer's advertised list is trusted. */
    readonly idTokenSignedResponseAlg?: string;
    /** Default: call UserInfo when the issuer publishes an endpoint. */
    readonly userInfo?: boolean;
    /** Clock skew tolerated on JWT time claims. Default 30. */
    readonly clockToleranceSeconds?: number;
    /** The fetch every upstream request goes through — a proxy, or a test seam. */
    readonly fetch?: typeof fetch;
    readonly redirectAllowlist?: readonly string[];
    readonly sessionDomain?: string;
    readonly authCallbackUrl?: string;
    readonly clientUrl?: string;
}
export type OidcProvider = FederationProvider & SupportsRefresh & SupportsClaimMapping & Partial<SupportsLogout>;
/** A federation name is the `:name` route segment and the identity prefix; keep it to one plain segment. */
export declare function checkFederationName(name: unknown): asserts name is string;
export declare function createOidcProvider(name: string, config: OidcProviderConfig): Promise<OidcProvider>;
//# sourceMappingURL=oidc.d.mts.map