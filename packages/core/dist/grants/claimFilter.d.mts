import type { UserSessionClaims } from "../user-sessions/types.mjs";
/**
 * OIDC-standard claim filter. Maps {@link UserSessionClaims} to the JWT-shaped
 * claim subset that the requested scopes authorize.
 *
 * Scope → claim mapping (strict whitelist):
 *   - profile  → name, picture
 *   - email    → email, email_verified (note the OIDC snake_case name)
 *   - groups   → groups (non-standard, opt-in per spec Section 6.4)
 *
 * `openid` scope itself yields no claim here — it governs whether id_token is
 * issued at all; `sub` is added by the caller (`generateIdToken`).
 *
 * Provider-specific claims (e.g. Google `hd`) are NEVER emitted — consumers
 * that need them must opt in via a custom scope mapping (out of scope for v1).
 */
export declare function filterClaimsByScope(claims: UserSessionClaims, scopes: ReadonlyArray<string>): Record<string, unknown>;
//# sourceMappingURL=claimFilter.d.mts.map