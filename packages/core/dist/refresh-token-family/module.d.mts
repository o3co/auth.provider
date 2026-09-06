/**
 * Memory-backed RefreshTokenFamilyStore module. Test + dev only — no
 * persistence across restarts. Ships in @o3co/auth-provider-core.
 *
 * Per A3 §8.1.
 */
export declare const memoryRefreshTokenFamilyStoreModule: import("@o3co/auth-provider-core").Module;
/**
 * Default RefreshTokenFamilyRotation wrapper module. Composes the storage
 * primitive into the 4-outcome rotation ceremony. Replaceable via DI:
 * consumers wanting custom rotation policy (audit-emitting, grace-period,
 * etc.) provide a module with `provides: { refreshTokenFamilyRotation: ... }`
 * INSTEAD of this one — boot planner enforces uniqueness via
 * BootError({ reason: "duplicate-provides" }).
 *
 * Per A3 §8.1.
 */
export declare const defaultRefreshTokenFamilyRotationModule: import("@o3co/auth-provider-core").Module;
/**
 * Default RefreshTokenFamilyRevocation wrapper module. Composes the
 * storage primitive into the idempotent revoke + read-only check.
 *
 * Per A3 §8.1.
 */
export declare const defaultRefreshTokenFamilyRevocationModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=module.d.mts.map