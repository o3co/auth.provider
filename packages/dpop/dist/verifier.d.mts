/**
 * DPoP proof verifier — `createDPoPMechanism` factory.
 *
 * Implements the RFC 9449 §6 validation sequence (15 steps) for the
 * token endpoint. Step ordering follows the spec's taxonomy:
 *
 *   Step 1:  DPoP header presence check  (null when absent)
 *   Step 2:  Single header value         (throw on comma)
 *   Steps 3–9, 13: parseProof (structural + JWK + claims + jkt thumbprint)
 *   Step 5:  alg whitelist               (after parseProof, uses proof.alg)
 *   Step 8:  Signature verification      (importJWK + jwtVerify)
 *   Step 10: htm match
 *   Step 11: htu match (both sides normalized)
 *   Step 12: iat window
 *   Step 14: Replay check (atomic seen) — wrapped so transport faults
 *            surface as `replay_store_unavailable` audit signal rather
 *            than leaking raw Redis errors through `tokenBindingMw`.
 *   Step 15: Return TokenBinding
 *
 * The verifier relies on `parseProof` (Sub-PR 2a) for steps 3–9 + 13 and
 * reuses the `jkt` already computed there (no re-derive in this layer).
 *
 * Per Wave 2 Phase 2 spec §6 + §8 factory contract.
 */
import type { Logger, TokenBindingMechanism } from "@o3co/auth-provider-core";
import type { DPoPReplayStore } from "./replay-store.mjs";
export interface DPoPMechanismOptions {
    /** Replay protection store. */
    readonly replayStore: DPoPReplayStore;
    /**
     * Acceptance window for the `iat` claim in seconds.
     * Default: 60 (1 minute).
     */
    readonly iatWindowSeconds?: number;
    /**
     * Allowlist of JOSE `alg` values. Proofs using any other algorithm are
     * rejected with `alg_not_allowed`. Default: ES256, ES384, EdDSA, RS256.
     */
    readonly algWhitelist?: readonly string[];
    /**
     * TTL in seconds for replay entries in the store. Default: 300 (5 minutes).
     * SHOULD be at least `iatWindowSeconds` to cover the acceptance window.
     */
    readonly replayTtlSeconds?: number;
    readonly logger?: Logger;
}
/**
 * Create a DPoP `TokenBindingMechanism` for use with `tokenBindingMw`.
 *
 * The returned mechanism:
 *   - Returns `null` when the `DPoP` header is absent (non-DPoP request).
 *   - Throws `DPoPError` for any proof invalidity.
 *   - Returns `{ kind: "dpop", confirmation: { jkt } }` on success.
 *
 * The `jkt` in the confirmation is the RFC 7638 SHA-256 thumbprint of the
 * proof's JWK, computed by `parseProof` (Sub-PR 2a) — not re-derived here.
 *
 * Per Wave 2 Phase 2 spec §8 (factory contract) + §6 (validation sequence).
 */
export declare const createDPoPMechanism: (options: DPoPMechanismOptions) => TokenBindingMechanism;
//# sourceMappingURL=verifier.d.mts.map