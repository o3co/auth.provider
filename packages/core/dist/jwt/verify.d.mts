import { type JWTPayload as JoseJWTPayload, type ProtectedHeaderParameters } from "jose";
import { type KeyStore } from "../keys/KeyStore.mjs";
import type { Logger } from "../logging/Logger.mjs";
/**
 * Token type — drives default `typ` expectation and selects appropriate
 * post-signature claim checks (e.g. `azp` on refresh tokens).
 */
export type JwtType = "access_token" | "refresh_token" | "id_token";
/**
 * Discriminator for {@link JwtVerificationError}. One reason per failure mode
 * keeps caller `catch` blocks structurally exhaustive when the exhaustive
 * switch over this union is type-checked.
 */
export type JwtVerificationReason = "alg" | "iss" | "aud" | "typ" | "azp" | "nonce" | "signature" | "expired" | "not_yet_valid" | "kid_unknown" | "kid_expired";
/**
 * Thrown by {@link verifyJwt} on any verification failure. The `reason` field
 * is the audit-stable discriminator; `message` is a human-readable summary
 * suitable for `logger.warn` but NOT for client-facing error responses
 * (callers must map to RFC-compliant error envelopes themselves).
 */
export declare class JwtVerificationError extends Error {
    readonly reason: JwtVerificationReason;
    readonly name = "JwtVerificationError";
    constructor(reason: JwtVerificationReason, message: string);
}
export interface JwtVerifyOptions {
    /** Token type — selects default `typ` expectation. */
    readonly type: JwtType;
    /**
     * Required `iss` claim — exact match. Pass an empty string to skip iss
     * pinning when the operator has not configured `oauth.jwt.issuer` and
     * the call site has no other source of expected issuer; the verifier
     * emits a `jwt_verify_iss_skipped` warning so the gap is audit-visible.
     */
    readonly expectedIssuer: string;
    /**
     * Required `aud` claim — must be present (string) or contain (array).
     *
     * Optional only because bearer-as-credential routes (introspect Bearer
     * self-intro, /userinfo, /logout id_token_hint) cannot establish the
     * calling-client identity *before* JWT verification, so the audience to
     * pin against is unknown at the verify call. At those sites the caller
     * passes `undefined`; the verifier emits a `jwt_verify_aud_skipped`
     * warning so the gap is audit-visible. All sites that DO know the
     * calling client (token / refresh / federation / token-exchange) MUST
     * supply this.
     */
    readonly expectedAudience?: string | readonly string[];
    /**
     * Optional `azp` claim binding. When provided, `payload.azp` must equal
     * this value or verification fails with `reason: "azp"`. Used by refresh
     * token verification to bind the RT to the authorized party (D-6 PB-2).
     */
    readonly expectedAzp?: string;
    /**
     * Optional `nonce` claim binding. Used by id_token verification to bind
     * the token to the original authorization request (PB-4+5).
     */
    readonly expectedNonce?: string;
    /**
     * Clock skew tolerance in milliseconds applied to `exp`/`nbf`/`iat`
     * checks. Default: 300_000 (5 min) per RFC 8725 §3.10 guidance.
     */
    readonly clockSkewMs?: number;
    /**
     * Override default `typ` for this {@link JwtType}. Pass `null` to skip
     * `typ` checking entirely (legacy migration paths only).
     */
    readonly expectedTyp?: string | null;
    /**
     * Override expected algorithms passed to jose. Default: `[keyStore.algorithm]`.
     * Setting an explicit list is required when verifying tokens issued by an
     * upstream provider whose alg differs from the local KeyStore.
     */
    readonly expectedAlgs?: readonly string[];
    /**
     * Audit logger. All rejection paths emit a structured warn record with
     * `{reason, jti, sub, iss, typ}` bindings so SIEM filters can index by
     * reason without scraping message text. Optional — when absent the
     * rejection is silent (caller handles it via the thrown error).
     */
    readonly logger?: Logger;
    /**
     * SF-1 transition flag for the v0.4.x→v0.5.x typ-header rollout.
     *
     * The default is `false`: tokens whose `typ` header is absent are
     * rejected. Operators with v0.4.x tokens still in circulation can set
     * this to `true` for their own bounded migration window — when true,
     * typ-less tokens are accepted and emit a `jwt_verify_legacy_typ`
     * warning. The v0.5.x default was `true`; Phase G S2 flips it.
     */
    readonly legacyTypAccept?: boolean;
}
export interface VerifiedJwt {
    readonly payload: JoseJWTPayload;
    readonly header: ProtectedHeaderParameters;
    readonly type: JwtType;
}
/**
 * Centralized JWT verification with alg / iss / aud / typ pinning.
 *
 * The verifier:
 *  1. decodes the protected header (without signature check) to read `kid`
 *     and `typ`,
 *  2. validates `typ` against the expected value (legacy compat is opt-in
 *     via {@link JwtVerifyOptions.legacyTypAccept}),
 *  3. resolves the verification key by `kid` via
 *     {@link KeyStore.getVerificationKey} (falls back to the current signing
 *     kid when the JWT has no `kid` header),
 *  4. delegates to jose `jwtVerify` with explicit `algorithms`, `issuer`, and
 *     `audience` options — pinning all three at the security-critical layer,
 *  5. enforces `iat <= now + clockSkewMs` post-signature (jose does not
 *     validate `iat`-in-future by default), and
 *  6. enforces optional `azp` / `nonce` claim bindings post-signature.
 *
 * On any failure the verifier throws {@link JwtVerificationError} with a
 * stable {@link JwtVerificationReason}. Callers map that to their own error
 * envelope (e.g. RFC 6749 `error: "invalid_token"`).
 */
export declare function verifyJwt(jwt: string, keyStore: KeyStore, options: JwtVerifyOptions): Promise<VerifiedJwt>;
//# sourceMappingURL=verify.d.mts.map