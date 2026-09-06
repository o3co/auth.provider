/**
 * Best-effort JWT payload decode without signature verification.
 *
 * Internal to the webauthn grant — only used to read `jti` / `exp` back off a
 * refresh token this package just minted itself, so the token can be
 * registered with a `RefreshTokenFamilyRotation`. Do NOT use it on a token
 * received from a caller: an unverified decode trusts whatever the caller
 * sent.
 *
 * Duplicated from packages/oauth/src/grants/_jwtPayload.mts for the same
 * reason `_resourceIndicator.mts` is: the webauthn package does not depend on
 * @o3co/auth-provider-oauth, and that file is file-internal to oauth/grants/
 * rather than barrel-exported.
 *
 * Returns an empty object on any parse error; callers must treat missing
 * fields as normal.
 */
export declare function decodeJwtPayload(token: string): Record<string, unknown>;
//# sourceMappingURL=_jwtPayload.d.mts.map