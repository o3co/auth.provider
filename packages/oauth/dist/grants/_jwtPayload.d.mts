/**
 * Best-effort JWT payload decode without signature verification.
 *
 * Internal to grants/ — only used to extract jti/exp/family_id from tokens
 * we just minted ourselves for the purpose of registering them with a
 * RefreshTokenStore. Do NOT use this on tokens received from clients
 * without a prior jwtVerify — an unsigned decode trusts the caller's
 * token format implicitly.
 *
 * Returns an empty object on any parse error; callers must treat missing
 * fields as normal.
 */
export declare function decodeJwtPayload(token: string): Record<string, unknown>;
//# sourceMappingURL=_jwtPayload.d.mts.map