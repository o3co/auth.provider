import type { KeyStore } from "../keys/KeyStore.mjs";
import type { Token } from "./token.mjs";
/**
 * Options for `generateLogoutToken` (OIDC Back-Channel Logout 1.0).
 */
export interface GenerateLogoutTokenOptions {
    /** Issuer URL (MUST match the id_token `iss` claim for the session being logged out). */
    readonly issuer: string;
    /** Subject identifier of the user being logged out. */
    readonly sub: string;
    /** Audience — the client_id of the RP receiving this logout_token. */
    readonly aud: string | string[];
    /** Session identifier (MUST match the id_token `sid` claim when present). */
    readonly sid?: string;
    /**
     * Whether to include the `sid` claim. Defaults to `true` for security — most RPs
     * require sid to correlate the logout with their local session. Set to `false`
     * only when the RP registered with `backchannel_logout_session_required: false`.
     */
    readonly includeSid?: boolean;
    /** JWT signer. */
    readonly keyStore: KeyStore;
    /** TTL in seconds. Defaults to 300 (5 minutes) per Back-Channel Logout 1.0 best practice. */
    readonly expiresIn?: number;
}
export declare const BACKCHANNEL_LOGOUT_EVENT_URI = "http://schemas.openid.net/event/backchannel-logout";
/**
 * Generates a signed logout_token JWT (OIDC Back-Channel Logout 1.0 §2.4).
 *
 * Claim composition:
 *   - iss, sub, aud (required)
 *   - iat, exp (seconds since epoch; default TTL 300s)
 *   - jti (unique token identifier)
 *   - events: { [BACKCHANNEL_LOGOUT_EVENT_URI]: {} } (required by spec)
 *   - sid (session identifier; included by default, omit with includeSid: false)
 *
 * Spec constraints enforced:
 *   - nonce MUST NOT be present (§2.4)
 *   - typ header set to "logout+jwt"
 */
export declare function generateLogoutToken(opts: GenerateLogoutTokenOptions): Promise<Token>;
//# sourceMappingURL=logoutToken.d.mts.map