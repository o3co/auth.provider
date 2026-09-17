import { type AccessTokenDenylist, type ClientRepository, type KeyStore, type Logger, type RefreshTokenFamilyRevocation } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
type ExpressLike = {
    Router: () => Router;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
};
export interface RevokeRouterOptions {
    readonly clientRepository: ClientRepository;
    readonly keyStore: KeyStore;
    readonly refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
    readonly accessTokenDenylist?: AccessTokenDenylist;
    readonly logger: Logger;
    readonly issuer: string;
}
/**
 * Creates an Express router handling `POST /revoke` per RFC 7009.
 *
 * Behavior summary:
 * - Requires client authentication (both confidential and public clients per RFC 7009 §2.1;
 *   public clients identify via `client_id` form param only — `allowPublicClients: true`).
 * - Accepts `token` + optional `token_type_hint` form params.
 * - Returns 400 `invalid_request` when `token` is absent.
 * - Returns 400 `unsupported_token_type` when `token_type_hint` is present
 *   but not a recognized value.
 * - ALWAYS returns 200 for all other outcomes (RFC 7009 §2.2 no-info-leak).
 *
 * Refresh-token path:
 * - Verifies the RT signature / type / issuer via `verifyJwt` with
 *   `ignoreExpiration: true` (revoking an expired RT is harmless idempotency
 *   per RFC 7009 §2.1).
 * - Extracts `family_id` claim; if absent or verification fails → silent 200.
 * - Verifies client ownership via `azp` (falls back to `aud`).
 * - Calls `refreshTokenFamilyRevocation.revokeFamily(familyId)`.
 * - When `refreshTokenFamilyRevocation` slot is unwired → silent 200.
 *
 * Access-token path:
 * - Verifies AT signature / type / issuer with `ignoreExpiration: true`
 *   (revoking an already-expired AT is also harmless).
 *
 * `ignoreExpiration: true` is allowed at both call sites within this file but
 * NOWHERE else in the codebase — CI lint guardrail T7 enforces this scoping
 * (see `.github/workflows/ci.yml` step `Restrict ignoreExpiration use-site`).
 * - Extracts `jti`, `exp`, `client_id` (or `azp` fallback) from payload.
 * - Verifies client ownership; mismatch → silent 200.
 * - When `accessTokenDenylist` slot is wired: calls `denylist.add(jti, exp * 1000)`.
 * - When `accessTokenDenylist` slot is unwired: logs warn + silent 200.
 */
export declare function createRevokeRouter(express: ExpressLike, opts: RevokeRouterOptions): Router;
export {};
//# sourceMappingURL=revoke.d.mts.map