/** The `at_hash` value for `accessToken` on an id_token signed with `alg`. */
export declare function computeAtHash(accessToken: string, alg: string): string;
/** Throws unless `atHash` is the claim `idToken` should carry for `accessToken`. */
export declare function verifyAtHash(label: string, idToken: string, accessToken: string, atHash: unknown): void;
//# sourceMappingURL=at-hash.d.mts.map