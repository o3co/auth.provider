import type { KeyStore, RefreshTokenFamilyRevocation } from "@o3co/auth-provider-core";
import type { ExchangeTokenValidator } from "./types.mjs";
export declare const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
export interface CreateSelfIssuedAccessTokenValidatorOptions {
    keyStore: KeyStore;
    refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
    issuer: string;
}
/**
 * Built-in validator for RFC 8693 subject_token_type=access_token when the
 * token was issued by this auth.provider instance. Verifies:
 *   - JWT signature (via KeyStore)
 *   - `typ: "at+jwt"` header (rejects id_tokens and logout_tokens even
 *     when signed by the same KeyStore — prevents token-type-confusion)
 *   - Standard claims (exp via jose)
 *   - Issuer match (always — `issuer` is a required option)
 *   - When refreshTokenFamilyRevocation is wired: family_id cascading revoke
 *
 * When refreshTokenFamilyRevocation is absent, the family revoke check is silently
 * skipped here; the grant handler is responsible for detecting this
 * misconfiguration and responding with invalid_grant (spec §7.2 state 1:
 * "not wired"). The validator alone is NOT fail-closed against store
 * misconfiguration.
 *
 * `issuer` is required; the constructor throws synchronously when it is
 * missing or an empty string. Without an issuer to compare against, an
 * at+jwt signed by the same KeyStore but with a different (or absent) `iss`
 * claim could be accepted — exactly the token-type-confusion gap Copilot
 * flagged on PR #100.
 *
 * Throws on infrastructure failures (store unavailable during runtime).
 * Returns null on validation failures (bad signature, wrong typ, missing/empty sub,
 * expired, revoked, issuer mismatch).
 */
export declare function createSelfIssuedAccessTokenValidator(options: CreateSelfIssuedAccessTokenValidatorOptions): ExchangeTokenValidator;
//# sourceMappingURL=selfIssuedAccessToken.d.mts.map