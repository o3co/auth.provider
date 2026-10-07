import type { User, UserSessionClaims } from "@o3co/auth-provider-core";
/**
 * Picks UserSessionClaims-shaped fields off a User. Used by LOCAL and
 * FEDERATION login paths to seed the session's claims envelope.
 *
 * Moved from `@o3co/auth-provider-core/user-sessions/claims.mts` (deleted in
 * Phase 8d's T29) into the session package because it has only 2 callers,
 * both inside this package.
 */
export declare function extractUserClaims(user: User): UserSessionClaims;
//# sourceMappingURL=extractUserClaims.d.mts.map