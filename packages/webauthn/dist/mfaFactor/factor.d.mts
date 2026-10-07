import { type MfaFactor } from "@o3co/auth-provider-core";
import type { WebAuthnConfig } from "../config.mjs";
/** The kind a WebAuthn factor's records carry, and the key it is contributed under. */
export declare const WEBAUTHN_MFA_FACTOR_KIND = "webauthn";
/** The user verification a ceremony asks for (WebAuthn §5.8.6). */
export type UserVerificationRequirement = "required" | "preferred" | "discouraged";
/** What the factor is built with. */
export interface WebAuthnMfaFactorSettings {
    /** The relying party the `webauthnConfig` slot holds: its id, name, origins and challenge lifetime. */
    readonly relyingParty: WebAuthnConfig;
    /** What every ceremony asks for, and a verification requires when `required`. */
    readonly userVerification: UserVerificationRequirement;
}
/** The `webauthn` factor over `settings`. */
export declare function createWebAuthnMfaFactor(settings: WebAuthnMfaFactorSettings): MfaFactor;
//# sourceMappingURL=factor.d.mts.map