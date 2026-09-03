import { type JWK } from "jose";
export interface DPoPProofClaims {
    readonly htm: string;
    readonly htu: string;
    readonly iat: number;
    readonly jti: string;
}
/**
 * Result of structural DPoP proof parsing. Layout matches Wave 2 Phase 2
 * spec §5.3 — flat fields, with the proof-key JWK and its RFC 7638 SHA-256
 * thumbprint (`jkt`) computed at parse time so downstream consumers (the
 * verifier in 2b, the grant-side cnf claim in 2c) can route on the binding
 * identity without re-deriving the thumbprint.
 *
 * Signature verification is the verifier's responsibility (Sub-PR 2b) —
 * `parseProof` only validates JOSE shape and claim presence.
 */
export interface DPoPProof {
    /** Proof-of-possession public key from the JOSE protected header. */
    readonly jwk: JWK;
    /** JOSE `alg` header value (whitelist enforcement is in the verifier). */
    readonly alg: string;
    /** RFC 7638 SHA-256 thumbprint of `jwk` — the value used in `cnf.jkt`. */
    readonly jkt: string;
    readonly claims: DPoPProofClaims;
    /** Original raw JWT — needed for signature verification in 2b. */
    readonly raw: string;
}
/**
 * Parse a raw DPoP header value into a structured `DPoPProof`. Throws
 * `DPoPError` for malformed input — does NOT verify the signature or
 * validate semantic claims (htm, htu, iat). Those happen in the
 * verifier (T2.5 / Sub-PR 2b).
 *
 * Validation order follows spec §6 with one performance-driven deviation:
 *   Step 3: JWT shape (3 parts)
 *   Step 4: typ = dpop+jwt
 *   Step 5: alg present (whitelist check is in verifier)
 *   Step 6: jwk present in header
 *   Step 7: jwk is public-only (no private material — name-screened)
 *   Step 9: required claims present + correct types       ← runs BEFORE step 8
 *   Step 8: jkt computed via RFC 7638 SHA-256 thumbprint  ← runs LAST
 *
 * Step 8 is moved AFTER step 9 because `computeJkt` is the only cryptographic
 * operation in the parser (canonical JSON serialization + SHA-256). Cheap
 * structural / type checks run first so a proof with missing claims rejects
 * without burning the thumbprint cost. The spec authorizes this ordering —
 * §6's step numbering is the validation taxonomy, not a literal execution
 * sequence, since steps 7 and 9 don't depend on the jkt value.
 *
 * Per Wave 2 Phase 2 spec §6 + design principle §3.2 (total-order validation).
 */
export declare const parseProof: (raw: string) => Promise<DPoPProof>;
//# sourceMappingURL=proof.d.mts.map