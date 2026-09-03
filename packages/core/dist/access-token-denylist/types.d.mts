/**
 * Tracks revoked access-token jtis. Optional ComponentMap slot; when present,
 * verifyJwt consults `has(jti)` and `/oauth/revoke` AT path calls `add(jti, expiresAtMs)`.
 *
 * Wave 2 forward-compat: signature is `add(jti, expiresAtMs, options?)`. Wave 1
 * implementations omit `options` parameter and remain valid when Wave 2 adds DPoP `cnf` binding.
 */
export interface AccessTokenDenylist {
    readonly kind: string;
    add(jti: string, expiresAtMs: number): Promise<void>;
    has(jti: string): Promise<boolean>;
}
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly accessTokenDenylist?: AccessTokenDenylist;
    }
}
//# sourceMappingURL=types.d.mts.map