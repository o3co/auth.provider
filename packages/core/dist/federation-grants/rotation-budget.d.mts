import type { FederationGrantRotations } from "./types.mjs";
export interface FederationGrantRotationBudget {
    /** Rotations a window admits: a whole number of at least one. */
    readonly limit: number;
    readonly windowMs: number;
}
export declare const FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS: FederationGrantRotationBudget;
/** The budget the retrieval limits name, each part absent read as its default. */
export declare const federationGrantRotationBudget: (limits: {
    readonly rotationBudget?: number;
    readonly rotationWindowMs?: number;
}) => FederationGrantRotationBudget;
export type FederationGrantRotationBudgetJudgement = {
    readonly spent: false;
}
/** `retryAfterSeconds`: until the window closes, whole seconds rounded up, at least one. */
 | {
    readonly spent: true;
    readonly retryAfterSeconds: number;
};
/**
 * Whether a take at `nowMs` would be refused, by the store's rule: spent while
 * the window opened at `since` holds `limit` rotations and `nowMs` is before
 * `since + windowMs`. A `nowMs` behind `since` counts into the window. A `since`
 * that holds no instant is no window: the next take opens one.
 */
export declare function judgeFederationGrantRotationBudget(rotations: FederationGrantRotations | undefined, budget: FederationGrantRotationBudget, nowMs: number): FederationGrantRotationBudgetJudgement;
//# sourceMappingURL=rotation-budget.d.mts.map