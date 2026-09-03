import type { RefreshTokenFamilyRevocation, RefreshTokenFamilyStore } from "./types.mjs";
/**
 * Inputs for the RefreshTokenFamilyRevocation composition.
 * Per A3 §6.2.
 */
export interface RefreshTokenFamilyRevocationDeps {
    readonly refreshTokenFamilyStore: RefreshTokenFamilyStore;
}
/**
 * RefreshTokenFamilyRevocation composition.
 *
 * `revokeFamily` is idempotent: returning null from the updater on
 * already-revoked state classifies as "aborted" at the storage layer,
 * which the wrapper treats as success (the desired end-state is reached).
 * Same for not-found: the desired end-state (no live family) is already
 * present.
 *
 * `isFamilyRevoked` is read-only via findFamily; returns false if the
 * family does not exist or the `revoked` flag is false.
 *
 * Per A3 §6.2.
 */
export declare function createRefreshTokenFamilyRevocation(deps: RefreshTokenFamilyRevocationDeps): RefreshTokenFamilyRevocation;
//# sourceMappingURL=revocation.d.mts.map