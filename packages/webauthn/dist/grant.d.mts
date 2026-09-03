/**
 * WebAuthn grant handler — `urn:o3co:oauth:grant-type:webauthn` (spec §2.4).
 *
 * Flow:
 *   1. Parse `body.assertion` as AuthenticationResponseJSON. Malformed → 400 invalid_grant.
 *   2. Extract challenge from assertion.response.clientDataJSON (base64url JSON).
 *   3. Look up credential via credentialStore.findByCredentialId(assertion.id).
 *      Not found → 400 invalid_grant.
 *   4. Consume challenge via challengeCeremony.consume("webauthn:authentication", value).
 *      outcome !== "consumed" → 400 invalid_grant.
 *   5. Verify assertion via verifyWebAuthnAssertion. ok=false → 400 invalid_grant.
 *   6. Atomic CAS sign-count update via credentialStore.updateSignCount.
 *      Returns false → 400 invalid_grant (concurrent race / clone attack).
 *   7. Optional grantPolicy gate — rt-style: called unconditionally when deps.grantPolicy
 *      is wired (Codex Round 3 P1). The resourceIndicator flag gates ONLY whether
 *      body.resource is forwarded in the request payload (Stage 1 plumbing contract).
 *      CP-18 fail-closed — policy throw → 503 temporarily_unavailable.
 *
 *      SECURITY: webauthn grant has no client.allowedScopes ceiling (the passkey is
 *      the auth event, not scope authorization). Policy is the ONLY scope-bounding gate.
 *      Deployments wanting scope authorization MUST wire grantPolicy.
 *
 *   8. Issue access token. No refresh token (Wave 1 first slice, spec §2.4).
 *
 * Audience derivation:
 *   - When ctx.authenticatedClient is present: allowedAudiences[0] ?? issuer ?? null
 *   - When no authenticated client: issuer ?? null
 *   (WebAuthn grant does not require client authentication — the passkey IS the
 *    authentication event. Consumers may optionally wire clientAuthMw before this
 *    handler to bind tokens to a specific client application.)
 *
 * RFC 8707 Stage 1 (Wave 1 §5.3):
 *   - resource forwarded to grantPolicy when resourceIndicator.enabled === true
 *   - Library-layer audience binding enforcement deferred to Stage 2 (issue #173)
 *
 * extractResourceParam: duplicated from packages/oauth/src/grants/_resourceIndicator.mts
 * because the webauthn package does not depend on @o3co/auth-provider-oauth and that
 * helper is explicitly NOT barrel-exported. Consolidation candidate for Wave 2.
 *
 * Cross-refs: Plan T30 / spec §2.4 / PR #172 W1P3 patterns / Codex Round 3 P1
 */
import { type ChallengeCeremony, type GrantDependencies, type GrantHandler, type WebAuthnCredentialStore } from "@o3co/auth-provider-core";
export declare const WEBAUTHN_GRANT_TYPE = "urn:o3co:oauth:grant-type:webauthn";
/**
 * Dependencies for the WebAuthn grant handler.
 *
 * `webauthnCredentialStore` and `challengeCeremony` are required for the
 * WebAuthn assertion flow; `webauthnConfig` carries the RP config (rpId,
 * allowed origins) needed for verifyWebAuthnAssertion.
 *
 * All other slots mirror the standard GrantDependencies shape (config, keyStore,
 * optional grantPolicy).
 */
export interface WebAuthnGrantDeps extends GrantDependencies {
    readonly webauthnCredentialStore: WebAuthnCredentialStore;
    readonly challengeCeremony: ChallengeCeremony;
    readonly webauthnConfig: {
        readonly rpId: string;
        readonly origin: readonly string[];
        /**
         * WebAuthn UserVerificationRequirement (W3C §5.8.6).
         *
         * Threaded through to verifyWebAuthnAssertion so SimpleWebAuthn enforces
         * the UV flag when the deployment sets userVerification = "required".
         *
         * Cross-refs: Codex Round 2 P1-1 / spec §2.5
         */
        readonly userVerification: "required" | "preferred" | "discouraged";
    };
}
/**
 * Creates a GrantHandler for the `urn:o3co:oauth:grant-type:webauthn` grant type.
 *
 * @param deps - Injected dependencies (credential store, challenge ceremony,
 *   RP config, optional grant policy).
 * @returns GrantHandler compatible with GrantRegistry.
 */
export declare const createWebAuthnGrant: (deps: WebAuthnGrantDeps) => GrantHandler;
//# sourceMappingURL=grant.d.mts.map