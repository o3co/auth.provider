import { type FederationClientSecret } from "@o3co/auth-provider-session";
/**
 * Client authentication at the upstream token endpoint (#524).
 *
 * Two methods, chosen by which credential the config carries:
 *
 * - `clientSecret` → `client_secret_basic` (RFC 6749 §2.3.1). The secret may
 *   be a resolver, consulted on every token request, so a deployment that
 *   rotates secrets never has to restart.
 * - `privateKey` → `private_key_jwt` (RFC 7523 §2.2 / OIDC Core §9). A
 *   PEM-encoded PKCS#8 key; the JWS algorithm is inferred from the key type
 *   unless `alg` says otherwise, and `kid` is put in the assertion header so
 *   the IdP can pick the key from the client's registered JWKS.
 *
 * Exactly one of the two: a config with both is ambiguous, one with neither
 * cannot authenticate, and each is refused at construction rather than at the
 * first login.
 */
export interface OidcPrivateKey {
    /** PEM-encoded PKCS#8 private key (`-----BEGIN PRIVATE KEY-----`). */
    readonly pem: string;
    /** `kid` for the assertion header, matching the key's entry in the client's JWKS. */
    readonly kid?: string;
    /** JWS algorithm; inferred from the key type when absent (RS256, ES256/384/512, EdDSA). */
    readonly alg?: string;
}
export interface OidcClientCredentials {
    readonly clientSecret?: FederationClientSecret;
    readonly privateKey?: string | OidcPrivateKey;
}
/**
 * The client-authentication hook openid-client applies to every token-endpoint
 * request — structurally `oidc.ClientAuth`, declared here so the vendor type
 * does not surface in this package's public declarations (CI's vendor-leak
 * guard keeps `openid-client` out of every `.d.mts`). Its one consumer,
 * `oidc.mts`, narrows it back at the call site.
 */
export type OidcClientAuth = (...args: never[]) => void | Promise<void>;
/** `client_secret_basic` with a secret that may be resolved per request. */
export declare function clientSecretBasic(clientSecret: FederationClientSecret): OidcClientAuth;
/** `private_key_jwt` from a PEM key, importing it once at construction. */
export declare function privateKeyJwt(label: string, privateKey: string | OidcPrivateKey): Promise<OidcClientAuth>;
/** The one client authentication method the credentials describe. */
export declare function clientAuthFor(label: string, credentials: OidcClientCredentials): Promise<OidcClientAuth>;
//# sourceMappingURL=client-auth.d.mts.map