/**
 * Declarative manifest for the WebAuthn passkey module.
 *
 * Consumer composition roots provide `webauthnConfig` via a small bootstrap
 * module that reads from application config (per A5 §10.2 const-Module
 * pattern). This module does NOT read from AppConfig directly —
 * WebAuthnConfig is a separate component slot (T21 ComponentMap augmentation).
 *
 * The three routes are mounted under dedicated sub-paths so they can
 * each carry individual IDs for collision detection and ordering:
 *   /oauth/webauthn/registration/options   — id: webauthn-registration-options
 *   /oauth/webauthn/registration/verify    — id: webauthn-registration-verify
 *   /oauth/webauthn/authentication/options — id: webauthn-authentication-options
 *
 * Rate-limit for authentication/options is composed externally — the handler
 * factory (T29) has no rateLimiter dep. Per project convention (S10/S15),
 * rate-limit middleware is wired at the route level via middleware composition,
 * not as a handler-factory dependency. To apply, wrap the handler inside an
 * Express router with the RateLimiter middleware before mounting.
 */
export declare const webauthnModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=module.d.mts.map