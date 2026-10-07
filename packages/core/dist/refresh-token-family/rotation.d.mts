import type { RefreshTokenFamilyRotation, RefreshTokenFamilyStore } from "./types.mjs";
/**
 * Inputs for the RefreshTokenFamilyRotation composition.
 * Per A3 §6.1.
 */
export interface RefreshTokenFamilyRotationDeps {
    readonly refreshTokenFamilyStore: RefreshTokenFamilyStore;
}
/**
 * RefreshTokenFamilyRotation composition: builds a fresh
 * RefreshTokenFamily aggregate on `register`, and translates
 * RefreshTokenFamilyStore.updateFamily outcomes into the 4-variant
 * RefreshTokenFamilyRotationOutcome on `rotate`.
 *
 * The closure-captured `abortReason` is reset at the top of every updater
 * invocation so CAS retries observe the freshest classification (the LAST
 * updater invocation determines the abort reason).
 *
 * Defence-in-depth fallback `?? "replayed"` on the aborted branch: if a
 * future code path adds an abort case that forgets to set `abortReason`,
 * the safest classification is "replayed" (caller rejects either way;
 * defaulting to a reject-class outcome is fail-closed).
 *
 * Per A3 §6.1.
 */
export declare function createRefreshTokenFamilyRotation(deps: RefreshTokenFamilyRotationDeps): RefreshTokenFamilyRotation;
//# sourceMappingURL=rotation.d.mts.map