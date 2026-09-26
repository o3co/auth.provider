/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { decodeProtectedHeader, errors as joseErrors, jwtVerify, } from "jose";
import { ExpiredKidError } from "../keys/KeyStore.mjs";
/**
 * Thrown by {@link verifyJwt} on any verification failure. The `reason` field
 * is the audit-stable discriminator; `message` is a human-readable summary
 * suitable for `logger.warn` but NOT for client-facing error responses
 * (callers must map to RFC-compliant error envelopes themselves).
 */
export class JwtVerificationError extends Error {
    reason;
    name = "JwtVerificationError";
    constructor(reason, message) {
        super(message);
        this.reason = reason;
    }
}
const DEFAULT_TYP_BY_TYPE = {
    access_token: "at+jwt",
    refresh_token: "rt+jwt",
    id_token: "id+jwt",
};
/**
 * Maps the v0.3-era `payload.type` legacy claim back to a {@link JwtType}.
 * v0.3 tokens predated the `typ` header convention; refresh tokens emitted
 * `payload.type = "refresh"` instead. Unknown values map to `undefined`
 * (the verifier accepts them under `legacyTypAccept` rather than rejecting,
 * matching the philosophy that an unrecognized legacy hint is not evidence
 * of cross-type confusion).
 */
const LEGACY_PAYLOAD_TYPE_MAP = {
    refresh: "refresh_token",
    access: "access_token",
};
const DEFAULT_CLOCK_SKEW_MS = 300_000;
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
export async function verifyJwt(jwt, keyStore, options) {
    const { type, expectedIssuer, expectedAudience, expectedAzp, expectedNonce, clockSkewMs = DEFAULT_CLOCK_SKEW_MS, expectedTyp, expectedAlgs, logger, legacyTypAccept = false, } = options;
    let header;
    try {
        header = decodeProtectedHeader(jwt);
    }
    catch {
        const err = new JwtVerificationError("signature", "JWT header decode failed");
        emitRejection(logger, err, undefined, undefined);
        throw err;
    }
    // typ check — header-only, runs before signature as a cheap token-type-
    // confusion screen. typ is in the public protected header (not part of
    // the signed claims set), so checking it pre-signature is a no-op for an
    // attacker who controls the header but not the key; it does NOT add a
    // timing oracle since rejecting on typ short-circuits before the HMAC /
    // RSA op the attacker would otherwise time. Pre-signature placement also
    // short-circuits id_token / logout_token tokens reaching an at+jwt-only
    // route (they would still fail signature against the same KeyStore, but
    // failing here keeps the audit log honest about *why*).
    const effectiveExpectedTyp = expectedTyp === undefined ? DEFAULT_TYP_BY_TYPE[type] : expectedTyp;
    if (effectiveExpectedTyp !== null) {
        const headerTyp = header.typ;
        if (headerTyp === undefined) {
            if (legacyTypAccept) {
                logger?.warn({
                    reason: "typ",
                    typ: undefined,
                    expectedTyp: effectiveExpectedTyp,
                }, "jwt_verify_legacy_typ");
            }
            else {
                const err = new JwtVerificationError("typ", `JWT typ header is required (expected ${effectiveExpectedTyp})`);
                emitRejection(logger, err, undefined, header);
                throw err;
            }
        }
        else if (headerTyp !== effectiveExpectedTyp) {
            const err = new JwtVerificationError("typ", `JWT typ ${headerTyp} does not match expected ${effectiveExpectedTyp}`);
            emitRejection(logger, err, undefined, header);
            throw err;
        }
    }
    // kid resolution — fall back to current signing kid when the JWT has no
    // kid header (back-compat with tokens signed before kid was emitted).
    const requestedKid = header.kid ?? keyStore.getSigningKidFallback();
    let verificationKey;
    try {
        verificationKey = await keyStore.getVerificationKey(requestedKid);
    }
    catch (cause) {
        // KeyStore distinguishes the two failure modes via typed errors
        // (ExpiredKidError / UnknownKidError) so SIEM pipelines can tell
        // operator-rotation expiry apart from attacker-fabricated header
        // values without coupling to message text.
        const reason = cause instanceof ExpiredKidError ? "kid_expired" : "kid_unknown";
        const message = cause instanceof Error ? cause.message : String(cause);
        const err = new JwtVerificationError(reason, message);
        emitRejection(logger, err, undefined, header);
        throw err;
    }
    const algorithms = expectedAlgs ?? [keyStore.algorithm];
    const clockSkewSeconds = Math.floor(clockSkewMs / 1000);
    // Audience pinning is OPT-IN. When the caller cannot establish the
    // expected audience before verification (introspect Bearer self-intro,
    // /userinfo, /logout id_token_hint — bearer-as-credential routes), the
    // jose `audience` option is omitted and the gap is logged so the audit
    // trail records that the aud check was deliberately skipped at this
    // site rather than silently bypassed.
    const audienceForJose = expectedAudience === undefined
        ? undefined
        : typeof expectedAudience === "string"
            ? expectedAudience
            : [...expectedAudience];
    if (expectedAudience === undefined) {
        // Once-per-(logger, reason, type) so /userinfo and other hot bearer-as-
        // credential routes don't flood ingestion with a warn record per request.
        // Operators see the gap on first occurrence; volume signal is preserved
        // in route-level request counters, not the audit log.
        warnAuditGapOnce(logger, "aud", type, { iss: expectedIssuer }, "jwt_verify_aud_skipped");
    }
    // Issuer pinning is normally required, but operators who haven't
    // configured `oauth.jwt.issuer` (e.g. partial-config test fixtures, dev
    // composition roots) still need verification to function. Empty-string
    // expectedIssuer is the explicit skip — different from passing a real
    // expected issuer so it's auditable.
    const skipIssuer = expectedIssuer === "";
    if (skipIssuer) {
        warnAuditGapOnce(logger, "iss", type, {}, "jwt_verify_iss_skipped");
    }
    let payload;
    try {
        const result = await jwtVerify(jwt, verificationKey, {
            algorithms: [...algorithms],
            ...(skipIssuer ? {} : { issuer: expectedIssuer }),
            ...(audienceForJose !== undefined ? { audience: audienceForJose } : {}),
            clockTolerance: clockSkewSeconds,
        });
        payload = result.payload;
    }
    catch (cause) {
        const reason = classifyJoseError(cause);
        const err = new JwtVerificationError(reason, cause instanceof Error ? cause.message : String(cause));
        emitRejection(logger, err, undefined, header);
        throw err;
    }
    // Legacy cross-type acceptance guard (Copilot review): when the header
    // `typ` was absent and `legacyTypAccept` waved through the typ check,
    // a v0.3-era token whose `payload.type` claim contradicts the expected
    // {@link JwtType} would otherwise pass — e.g. a typ-less RT carrying
    // `payload.type: "refresh"` accepted as an access token at /userinfo.
    // Map the legacy claim back to the type universe and reject contradictions.
    if (header.typ === undefined && typeof payload.type === "string") {
        const mappedType = LEGACY_PAYLOAD_TYPE_MAP[payload.type];
        if (mappedType !== undefined && mappedType !== type) {
            const err = new JwtVerificationError("typ", `JWT legacy payload.type ${payload.type} maps to ${mappedType}, expected ${type}`);
            emitRejection(logger, err, payload, header);
            throw err;
        }
    }
    // iat in future beyond skew — jose does not enforce this; RFC 8725 §3.10
    // recommends rejecting because a future iat indicates clock tampering or
    // token replay from a forged time source.
    if (typeof payload.iat === "number") {
        const nowSeconds = Math.floor(Date.now() / 1000);
        if (payload.iat > nowSeconds + clockSkewSeconds) {
            const err = new JwtVerificationError("not_yet_valid", `JWT iat ${payload.iat} is in the future beyond clock skew`);
            emitRejection(logger, err, payload, header);
            throw err;
        }
    }
    if (expectedAzp !== undefined && payload.azp !== expectedAzp) {
        const err = new JwtVerificationError("azp", `JWT azp ${String(payload.azp)} does not match expected ${expectedAzp}`);
        emitRejection(logger, err, payload, header);
        throw err;
    }
    if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
        const err = new JwtVerificationError("nonce", `JWT nonce mismatch (expected ${expectedNonce})`);
        emitRejection(logger, err, payload, header);
        throw err;
    }
    return { payload, header, type };
}
function classifyJoseError(cause) {
    if (cause instanceof joseErrors.JWTExpired) {
        return "expired";
    }
    if (cause instanceof joseErrors.JOSEAlgNotAllowed) {
        return "alg";
    }
    if (cause instanceof joseErrors.JWTClaimValidationFailed) {
        switch (cause.claim) {
            case "iss":
                return "iss";
            case "aud":
                return "aud";
            case "nbf":
            case "iat":
                return "not_yet_valid";
            case "exp":
                return "expired";
            default:
                // Unrecognized claim validation — fall through to generic
                // signature reason rather than invent a new bucket.
                return "signature";
        }
    }
    if (cause instanceof joseErrors.JWSSignatureVerificationFailed) {
        return "signature";
    }
    if (cause instanceof joseErrors.JWSInvalid || cause instanceof joseErrors.JWTInvalid) {
        return "signature";
    }
    return "signature";
}
function emitRejection(logger, err, payload, header) {
    if (!logger)
        return;
    logger.warn({
        reason: err.reason,
        jti: payload?.jti,
        sub: payload?.sub,
        iss: payload?.iss,
        typ: header?.typ,
    }, "jwt_verify_rejected");
}
/**
 * Per-logger once-per-(reason, type) memoization for audit-gap warnings
 * (`jwt_verify_aud_skipped`, `jwt_verify_iss_skipped`). Hot bearer-as-
 * credential routes (e.g. /userinfo) would otherwise emit one warn record
 * per request — operationally noisy and a real ingestion-cost issue.
 *
 * The map is keyed by Logger identity so each unique logger instance gets
 * its own dedupe set: production deployments with a singleton logger emit
 * each gap exactly once; tests that construct fresh mock loggers per case
 * see a fresh emission per test (so assertions on warn calls remain
 * deterministic). WeakMap auto-clears on logger GC.
 */
const auditGapEmitted = new WeakMap();
function warnAuditGapOnce(logger, reason, type, bindings, msg) {
    if (!logger)
        return;
    let seen = auditGapEmitted.get(logger);
    if (!seen) {
        seen = new Set();
        auditGapEmitted.set(logger, seen);
    }
    const key = `${reason}:${type}`;
    if (seen.has(key))
        return;
    seen.add(key);
    logger.warn({ reason, type, ...bindings }, msg);
}
