import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
export type RefreshTokenRotateOutcome = {
    readonly outcome: "rotated";
} | {
    readonly outcome: "replayed";
    readonly familyId: string;
} | {
    readonly outcome: "unknown";
} | {
    readonly outcome: "revoked";
};
export interface RefreshTokenStoreBase {
    readonly kind: string;
    /**
     * Atomically consume previousJti and register newJti. See spec Section
     * 2.4 for the full outcome matrix.
     */
    rotate(previousJti: string | null, newJti: string, familyId: string, expiresAt: Date): Promise<RefreshTokenRotateOutcome>;
    isFamilyRevoked(familyId: string): Promise<boolean>;
    revokeFamily(familyId: string): Promise<void>;
}
export type RefreshTokenStoreFactory = AdapterFactory<RefreshTokenStoreBase>;
//# sourceMappingURL=types.d.mts.map