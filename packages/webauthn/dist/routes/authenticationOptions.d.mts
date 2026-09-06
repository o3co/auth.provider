/**
 * POST /oauth/webauthn/authentication/options — authentication ceremony options endpoint.
 *
 * Returns a PublicKeyCredentialRequestOptionsJSON for the client to initiate a
 * WebAuthn authentication ceremony (passkey assertion).
 *
 * Security properties (spec §2.4):
 *   - Unauthenticated by design: the passkey authentication IS the authentication
 *     event, not a follow-up to one. No req.webauthnSubject check.
 *   - Rate-limit middleware is composed externally at module-wiring time
 *     (S10/S15 — RateLimiter slot). Not a handler-level dep.
 *   - Challenge is stored under the fixed, non-user-scoped namespace
 *     "webauthn:authentication". The userId is resolved post-assertion from the
 *     credential record returned by the authenticator — the client does NOT
 *     declare which user they are (that would be a proof-of-possession bypass).
 *   - Optional userId body field: if provided, allowCredentials is populated from
 *     the credential store; if absent, the discoverable-credentials flow is used
 *     (empty allowCredentials → authenticator prompts the user to pick a passkey).
 *   - Existence-leak mitigation: same 200 status regardless of whether userId
 *     maps to a real user or no user at all — no 404 or error-shape leak.
 *     Note: when userId IS provided AND has credentials, the allowCredentials
 *     array is non-empty, so the response shape differs from the no-credentials
 *     case. Full enumeration resistance requires the discoverable flow (omit
 *     userId) or consumer rate-limiting (S10/S15).
 *
 * NOT barrel-exported from the package index — internal to the webauthn module
 * until Task 31 wires the router.
 *
 * Cross-refs: Plan T29 / spec §2.4
 */
import type { ChallengeStore, WebAuthnCredentialStore } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import type { WebAuthnConfig } from "../config.mjs";
export interface AuthenticationOptionsDeps {
    readonly config: WebAuthnConfig;
    readonly challengeStore: ChallengeStore;
    readonly credentialStore: WebAuthnCredentialStore;
}
/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/authentication/options.
 *
 * Unauthenticated — no req.webauthnSubject check. Rate-limit middleware is
 * composed externally by the module router (Task 31).
 *
 * @param deps - Injected dependencies (config, challengeStore, credentialStore).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export declare function createAuthenticationOptionsHandler(deps: AuthenticationOptionsDeps): RequestHandler;
//# sourceMappingURL=authenticationOptions.d.mts.map