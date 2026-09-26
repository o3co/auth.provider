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
export function createRefreshTokenFamilyRevocation(deps) {
    return {
        async revokeFamily(familyId) {
            await deps.refreshTokenFamilyStore.updateFamily(familyId, (current) => {
                if (current.revoked)
                    return null; // already revoked, no-op
                // Freeze the updater return value mirroring rotation.mts (defence-in-depth).
                // Adapters also freeze returned families, but freezing here is the
                // declared updater convention so future wrapper code that reads the
                // returned family does not encounter a mutable handle.
                return Object.freeze({ ...current, revoked: true });
            });
            // All three RefreshTokenFamilyUpdateResult outcomes are valid success
            // paths for an idempotent revoke:
            //   - committed: flipped revoked: false -> true
            //   - aborted: already revoked
            //   - not-found: already GC'd or never existed
        },
        async isFamilyRevoked(familyId) {
            const family = await deps.refreshTokenFamilyStore.findFamily(familyId);
            return family?.revoked ?? false;
        },
    };
}
