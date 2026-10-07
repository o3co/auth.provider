/**
 * The tuning defaults for `mode = "full-pki"`, in one place.
 *
 * Two consumers need them and they must not drift: `mtlsConfigSchema`, which
 * fills them in for config that omits the keys, and `buildFullPkiValidator`,
 * which fills them in for a composition root that builds the mechanism
 * directly and bypasses the schema. Written twice, they would eventually
 * disagree, and the disagreement would be invisible — the second copy only
 * runs on the path nobody tests by default.
 *
 * ### Why these have defaults when `revocation` does not
 *
 * These three bound work and pin strength. Every deployment wants *a* value,
 * and a conservative one is right for almost all of them; getting the default
 * is not a decision anyone is dodging. `revocation.mode` and
 * `.on-unavailable` are different in kind: they trade an availability
 * incident against a window in which a revoked certificate still works, and
 * there is no answer that is right for every deployment. So those have no
 * defaults and `mtlsModule` refuses to boot without them.
 *
 * The failure mode this file closes is specific: a missing `max-chain-depth`
 * reaching `validate` as `undefined` makes `presented > undefined` evaluate
 * to `false`, so the depth guard silently never fires. A missing
 * `min-rsa-key-bits` does the same to the key-size floor. Both fail **open**,
 * and neither raises anything at boot.
 */
import { type SignatureAlgorithmName } from "./algorithms.mjs";
export interface FullPkiTuning {
    readonly maxChainDepth: number;
    readonly signatureAlgorithms: readonly SignatureAlgorithmName[];
    readonly minRsaKeyBits: number;
}
export declare const FULL_PKI_DEFAULT_MAX_CHAIN_DEPTH = 6;
export declare const FULL_PKI_DEFAULT_MIN_RSA_KEY_BITS = 2048;
export declare const FULL_PKI_DEFAULTS: FullPkiTuning;
/**
 * Fill in any tuning value a caller left unset.
 *
 * Deliberately tolerant of a partially-populated object rather than trusting
 * the declared type: the config that reaches here has crossed a HOCON parse
 * and an `as never` cast at the composition root, so the type is a claim
 * about the shape, not a guarantee of it.
 */
export declare const resolveFullPkiTuning: (partial: {
    readonly "max-chain-depth"?: number;
    readonly "signature-algorithms"?: readonly SignatureAlgorithmName[];
    readonly "min-rsa-key-bits"?: number;
} | undefined) => FullPkiTuning;
//# sourceMappingURL=defaults.d.mts.map