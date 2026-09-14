/**
 * Express Request augmentation for the WebAuthn package.
 *
 * Consumers writing upstream auth middleware that sets `req.webauthnSubject`
 * (per README guidance) should import `WebAuthnSubject` from this package.
 * Importing any export from `@o3co/auth-provider-webauthn` also merges the
 * `declare global` Express Request augmentation into the consumer's TypeScript
 * build.
 *
 * Declaration pattern follows `packages/oauth/src/middleware/clientAuth.mts`
 * (`req.oauthClient`). Uses the global Express namespace which is the stable
 * augmentation target for Express v4 and v5.
 *
 * Cross-refs: Plan T27 / spec §2.4 / PR #172 C3 fix
 */
/**
 * Authenticated subject required by WebAuthn registration endpoints.
 *
 * Set by upstream auth middleware (session cookie or Bearer token) before
 * any webauthn registration route is reached. Absent when the request has
 * not been authenticated.
 *
 * `userId` MUST be opaque and MUST NOT contain PII (email, username, etc.)
 * per WebAuthn §5.4.3 — it is used as the WebAuthn user-handle presented
 * to the authenticator and may be persisted and synced by the device.
 */
export interface WebAuthnSubject {
    readonly userId: string;
    readonly userName?: string;
    readonly userDisplayName?: string;
}
declare global {
    namespace Express {
        interface Request {
            /**
             * The authenticated WebAuthn subject, set by upstream session / bearer
             * middleware. Absent when the request has not been authenticated.
             */
            webauthnSubject?: WebAuthnSubject;
        }
    }
}
//# sourceMappingURL=request.d.mts.map