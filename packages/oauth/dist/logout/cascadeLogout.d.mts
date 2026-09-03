import type { FederationTokenStoreBase, Logger, RefreshTokenStoreBase, UserSessionStoreBase } from "@o3co/auth-provider-core";
export interface CascadeLogoutOptions {
    readonly sid: string;
    readonly familyIds: ReadonlyArray<string>;
    readonly refreshTokenStore: RefreshTokenStoreBase;
    readonly federationTokenStore: FederationTokenStoreBase;
    readonly userSessionStore: UserSessionStoreBase;
    /**
     * Optional structured logger for the step-2 best-effort warning.
     * Defaults to `console`. Provide a pino/winston/etc instance with a compatible
     * `warn(message, ...args)` signature to route failures into your observability stack.
     */
    readonly logger?: Logger;
}
export type CascadeLogoutResult = {
    readonly outcome: "done";
} | {
    readonly outcome: "failed";
    readonly step: 1 | 2 | 3;
    readonly error: unknown;
};
/**
 * Executes the three-step logout cascade in the fixed order mandated by spec
 * Section 14.2:
 *   1. revokeFamily (all families) — throw ⇒ 503 (steps 2+3 skipped; retry safe).
 *   2. deleteBySession (federation tokens) — best-effort; throw ⇒ warn + continue.
 *      Orphaned federation tokens eventually GC by TTL.
 *   3. delete (session record) — throw ⇒ 503 (steps 1+2 are idempotent, retry converges).
 *
 * Caller responsibilities:
 *   - Map `outcome: "failed"` to HTTP 503.
 *   - Run Back-Channel / Front-Channel / IdP-logout phases separately — this helper
 *     only handles the store cascade.
 *
 * @param opts.logger - Optional structured logger for the step-2 best-effort warning.
 *   Defaults to `console`. Provide a pino/winston/etc instance with a compatible
 *   `warn(message, ...args)` signature to route failures into your observability stack.
 */
export declare function cascadeLogout(opts: CascadeLogoutOptions): Promise<CascadeLogoutResult>;
//# sourceMappingURL=cascadeLogout.d.mts.map