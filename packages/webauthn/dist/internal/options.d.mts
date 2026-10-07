/**
 * Internal WebAuthn options-generation helpers (spec §2.4).
 *
 * Thin wrappers around `@simplewebauthn/server`'s `generateRegistrationOptions`
 * and `generateAuthenticationOptions` that:
 *   1. Map `WebAuthnConfig` fields to SimpleWebAuthn's parameter shape.
 *   2. Encode `userId` as a Uint8Array via TextEncoder (WebAuthn §5.4.3 —
 *      user.id is an opaque byte sequence, no PII per spec §2.3.2).
 *   3. Enable discoverable-credentials flow when `allowCredentials` is empty
 *      (pass `undefined` instead of `[]` per SimpleWebAuthn convention).
 *   4. Map `attestationPreference = "indirect"` → `"none"` because
 *      SimpleWebAuthn v13.1.1 removed "indirect" from its server-side API
 *      (`attestationType` accepts only `'direct' | 'enterprise' | 'none'`).
 *   5. Set `authenticatorSelection.residentKey = "preferred"` to enable
 *      discoverable credentials by default (WebAuthn §2.4).
 *
 * NOT exported from the package barrel — internal use only.
 *
 * Cross-refs: Plan T26 / spec §2.4 / WebAuthn §5.4.3 / §2.3.2
 */
import type { WebAuthnCredential } from "@o3co/auth-provider-core";
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/server";
import type { WebAuthnConfig } from "../config.mjs";
export declare function generateRegistrationOptionsForUser(args: {
    readonly config: WebAuthnConfig;
    /** Opaque user handle per WebAuthn §5.4.3 / spec §2.3.2. No PII stored here. */
    readonly userId: string;
    readonly userName: string;
    readonly userDisplayName: string;
    readonly excludeCredentials: readonly WebAuthnCredential[];
    readonly challenge: Uint8Array;
}): Promise<PublicKeyCredentialCreationOptionsJSON>;
export declare function generateAuthenticationOptionsForUser(args: {
    readonly config: WebAuthnConfig;
    /**
     * Credentials the user has previously registered.
     * Empty array → discoverable-credentials flow (pass undefined to SimpleWebAuthn
     * so the client browser prompts the user to pick an available passkey).
     */
    readonly allowCredentials: readonly WebAuthnCredential[];
    readonly challenge: Uint8Array;
}): Promise<PublicKeyCredentialRequestOptionsJSON>;
//# sourceMappingURL=options.d.mts.map