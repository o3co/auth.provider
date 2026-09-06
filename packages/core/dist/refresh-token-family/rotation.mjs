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
export function createRefreshTokenFamilyRotation(deps) {
    return {
        async register(newJti, familyId, expiresAtMs) {
            const family = Object.freeze({
                familyId,
                activeJti: newJti,
                revoked: false,
                expiresAtMs,
            });
            await deps.refreshTokenFamilyStore.registerFamily(family);
        },
        async rotate(previousJti, newJti, familyId, expiresAtMs) {
            let abortReason = null;
            const result = await deps.refreshTokenFamilyStore.updateFamily(familyId, (current) => {
                abortReason = null; // reset on every updater invocation
                if (current.revoked) {
                    abortReason = "revoked";
                    return null;
                }
                if (current.activeJti !== previousJti) {
                    abortReason = "replayed";
                    return null;
                }
                return Object.freeze({
                    ...current,
                    activeJti: newJti,
                    expiresAtMs,
                });
            });
            switch (result.outcome) {
                case "not-found":
                    return Object.freeze({ outcome: "unknown_family" });
                case "aborted":
                    return Object.freeze({
                        outcome: abortReason ?? "replayed",
                    });
                case "committed":
                    return Object.freeze({ outcome: "rotated" });
            }
        },
    };
}
