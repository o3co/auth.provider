/** The scope prefix DPoP records its proofs under: `dpop-proof:<jkt>`. */
export declare const DPOP_PROOF_REPLAY_SCOPE_PREFIX = "dpop-proof:";
/**
 * The share of the in-process seen-set's cap DPoP proofs may fill: 90%,
 * rounded up to a whole record but always a record short of the cap, so the
 * other consumers keep at least one (`min(ceil(0.9n), n − 1)`). A cap of one
 * has no reserve: its one record may be a proof.
 */
export declare const DPOP_PROOF_REPLAY_SHARE = 0.9;
//# sourceMappingURL=scopes.d.mts.map