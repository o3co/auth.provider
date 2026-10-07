import { type GrantDependencies, type GrantHandler } from "@o3co/auth-provider-core";
/**
 * `client_credentials` grant per RFC 6749 §4.4 + Wave 1 §3.
 *
 * Public clients (`tokenEndpointAuthMethod === "none"`) are rejected (§3.4):
 * RFC 6749 §4.4 limits the grant to confidential clients. Per-client
 * gating is via `AuthenticatedClient.allowedGrantTypes`: an absent or empty
 * list denies the grant (§3.4.1 deny-by-absence-only-for-`client_credentials`).
 *
 * The issued access token has `sub = client.clientId` (RFC 6749 §4.4.2: no
 * end-user) and no refresh token is issued (RFC 6749 §4.4.3).
 */
export declare const createClientCredentialsGrant: (deps: GrantDependencies) => GrantHandler;
//# sourceMappingURL=clientCredentials.d.mts.map