/**
 * RFC 7800 confirmation claim, narrowed to the binding methods this
 * library ships in Stage 1. Adding a future variant (e.g. RFC 9421
 * `jwk`) is a core semver-minor extension of this union — see Wave 2
 * Token-binding Cluster spec §4.3.
 */
export type Confirmation = {
    readonly jkt: string;
} | {
    readonly "x5t#S256": string;
};
//# sourceMappingURL=confirmation.d.mts.map