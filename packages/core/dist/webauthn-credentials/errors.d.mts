/**
 * Reasons emitted by `WebAuthnCredentialStorageError`.
 *
 * - `duplicate-credential`: registerCredential called for a credentialId that
 *   already exists. The colliding insert is rejected and the existing record is
 *   preserved unchanged. Surfaces loudly so callers can return a 400 to the
 *   registering client rather than silently overwriting (TOCTOU prevention).
 *
 * Per spec §2.3.1 + Codex Round 5 P2 finding.
 */
export type WebAuthnCredentialStorageErrorReason = "duplicate-credential";
/**
 * Single discriminated-reason error class for `WebAuthnCredentialStore`
 * adapter primitives. Mirrors `RefreshTokenStorageError` and
 * `ChallengeStorageError` shape: discriminated `reason` field, native
 * ES2022 `cause` for chaining underlying adapter errors, default message
 * templated from `reason`.
 *
 * Per spec §2.3.1.
 */
export declare class WebAuthnCredentialStorageError extends Error {
    readonly reason: WebAuthnCredentialStorageErrorReason;
    constructor(opts: {
        reason: WebAuthnCredentialStorageErrorReason;
        message?: string;
        cause?: unknown;
    });
}
//# sourceMappingURL=errors.d.mts.map