/**
 * POST /oauth/webauthn/registration/options — registration ceremony options endpoint.
 *
 * Returns a PublicKeyCredentialCreationOptionsJSON to be forwarded to the client.
 * Requires an authenticated subject on `req.webauthnSubject` — set by upstream
 * session / bearer middleware. Authorization strength is a consumer-policy concern;
 * this endpoint trusts upstream auth.
 *
 * Security properties (spec §2.4):
 *   - userId is taken from the authenticated session, NOT the request body —
 *     prevents victim-targeted enrollment (cross-user challenge injection).
 *   - Challenge is scoped to `webauthn:registration:${userId}` so a challenge
 *     issued for user A cannot be consumed by user B.
 *   - challengeTtlMs controls the window; default 120_000 ms per spec §2.4.1.
 *   - excludeCredentials is populated from the credential store to prevent
 *     re-registering an already-registered authenticator for this user.
 *
 * NOT barrel-exported from the package index — internal to the webauthn module
 * until Task 31 wires the router.
 *
 * Cross-refs: Plan T27 / spec §2.4 / §2.4.1
 */
import type { ChallengeStore, WebAuthnCredentialStore } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import type { WebAuthnConfig } from "../config.mjs";
export type { WebAuthnSubject } from "../request.mjs";
export interface RegistrationOptionsDeps {
    readonly config: WebAuthnConfig;
    readonly challengeStore: ChallengeStore;
    readonly credentialStore: WebAuthnCredentialStore;
}
/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/registration/options.
 *
 * @param deps - Injected dependencies (config, challengeStore, credentialStore).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export declare function createRegistrationOptionsHandler(deps: RegistrationOptionsDeps): RequestHandler;
//# sourceMappingURL=registrationOptions.d.mts.map