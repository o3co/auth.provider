/**
 * POST /oauth/webauthn/registration/verify — registration ceremony verify endpoint.
 *
 * Consumes the single-use challenge issued by the options endpoint, verifies the
 * authenticator's attestation response via SimpleWebAuthn, and persists the new
 * credential to the store.
 *
 * Security properties (spec §2.4):
 *   - Requires an authenticated subject on `req.webauthnSubject` (set by upstream
 *     session / bearer middleware). Returns 401 if absent.
 *   - Challenge is consumed atomically via ChallengeCeremony for the user-scoped
 *     namespace `webauthn:registration:${userId}`. Any outcome other than "consumed"
 *     (i.e. "unknown" or "replayed") immediately rejects with 400 challenge_invalid —
 *     replay rejection is the redemption primitive; no separate seen-challenge tracking.
 *   - userId is always taken from the authenticated session (req.webauthnSubject.userId),
 *     NOT from the request body — prevents victim-targeted enrollment.
 *   - nickname is validated: string, 1–64 characters (inclusive). Absent is valid;
 *     empty string is rejected. Limit: 64 chars (chosen to match common display-name
 *     field constraints; large enough for emoji and Unicode labels).
 *   - Multi-origin support: config.origin[] is passed to verifyWebAuthnAttestation (S7).
 *
 * NOT barrel-exported from the package index — internal to the webauthn module
 * until Task 31 wires the router.
 *
 * Cross-refs: Plan T28 / spec §2.4 / S7 multi-origin
 */
import { type ChallengeCeremony, type WebAuthnCredentialStore } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import type { WebAuthnConfig } from "../config.mjs";
export interface RegistrationVerifyDeps {
    readonly config: WebAuthnConfig;
    readonly challengeCeremony: ChallengeCeremony;
    readonly credentialStore: WebAuthnCredentialStore;
}
/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/registration/verify.
 *
 * @param deps - Injected dependencies (config, challengeCeremony, credentialStore).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export declare function createRegistrationVerifyHandler(deps: RegistrationVerifyDeps): RequestHandler;
//# sourceMappingURL=registrationVerify.d.mts.map