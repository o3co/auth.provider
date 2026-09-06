import type { AssertionVerifier, GrantDependencies, GrantHandler, UserRepository } from "@o3co/auth-provider-core";
/** RFC 7523 §2.1. */
export declare const JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/**
 * RFC 7523 JWT-bearer authorization grant, wired to the Store's
 * `authenticateByToken` seam (#301).
 *
 * ## The gap this closes
 *
 * `UserRepository.authenticateByToken(handle)` — "authenticate by an opaque
 * handle and resolve to a subject" — already existed and is service-pluggable,
 * but the only caller was the federation callback. There was no public entry
 * point for *present a device credential → authenticate → get tokens*, so the
 * device-login and anonymous→registered shapes had nowhere to land.
 *
 * ## Why RFC 7523 and not token exchange
 *
 * The issue's option (A) was a custom token-exchange validator, on the reading
 * that it "works today". It does not for this case: the exchange grant answers
 * `401 invalid_client` for `tokenEndpointAuthMethod === "none"` — *"Token
 * Exchange does not support public clients"* — and a device holding a signed
 * assertion is the archetypal public client. RFC 7523 §3 is the standard
 * written for this shape, and says client authentication is **optional**
 * ("JWT authorization grants may be used with or without client authentication
 * or identification"), which is the property token exchange refuses.
 *
 * RFC 7523 also leaves *how* the assertion is validated — "the key used to
 * apply and verify the digital signature" — explicitly out of scope, which is
 * what makes resolving it through a pluggable {@link AssertionVerifier} a
 * conforming choice rather than a deviation.
 *
 * ## Who may use it
 *
 * An authenticated client needs `allowedGrantTypes` to name this grant: the
 * handler declares `requiresExplicitGrantAllowlist`, so an absent allowlist
 * denies at dispatch (#326) rather than admitting by omission, the rule
 * `client_credentials` and the device grant already follow. A caller with no
 * client identity is outside that check by construction.
 *
 * ## The boundary this does not cross
 *
 * Verification proves **possession**; the Store decides **identity**. This
 * grant never inspects who the handle belongs to, never creates or links
 * anything, and never writes. A device that is not linked to a user is the
 * Store's business: it returns whatever subject it wants for that handle,
 * including a stable anonymous one, and continuity across a later signup is a
 * Store data-modelling choice. `UserRepository` stays `authenticate` /
 * `authenticateByToken` (#305's verify-only boundary).
 *
 * ## Failure vocabulary
 *
 * - Missing/blank `assertion` → `invalid_request` (RFC 6749 §5.2: a missing
 *   parameter is not a bad grant).
 * - Verifier returns `null`, the Store does not resolve the handle, or the
 *   resolved user fails `oauth.requireEmailVerified` (#297) → `invalid_grant`,
 *   identically. Distinguishing them would let a caller probe for live device
 *   identifiers, or for which of them are linked to a real account.
 * - Verifier or Store **throws** → `503 temporarily_unavailable`. An
 *   attestation service or a Store being unreachable is an outage, not a bad
 *   credential, and answering `invalid_grant` would send an operator to
 *   re-enrol a device that was fine — the distinction #408 drew for revocation.
 * - `grantPolicy`, when wired, runs after all of the above and fails closed
 *   (throw → `503`, deny → its own error, a widened scope → `invalid_scope`)
 *   — see `evaluateGrantPolicy`.
 */
export declare const createJwtBearerGrant: (deps: GrantDependencies & {
    readonly assertionVerifier: AssertionVerifier;
    readonly userRepository: UserRepository;
}) => GrantHandler;
//# sourceMappingURL=jwtBearer.d.mts.map