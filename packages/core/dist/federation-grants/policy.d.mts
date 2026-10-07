export interface FederationGrantPolicy {
    /**
     * `federation-grants.enabled`: whether federation grants exist in this
     * deployment, so that what ends a subject's access must end its grants too.
     */
    readonly enabled: boolean;
    /**
     * The keep policy in force: whether a subject-wide revocation may be asked
     * to leave the subject's established grants standing
     * (`federation-grants.allowKeepOnSubjectRevocation`, read with
     * `resolveFederationGrantKeepPolicy`). Always `false` while `enabled` is
     * `false`: an allowance to keep grants a deployment does not have is an
     * allowance over nothing, so a reader reads this member alone.
     */
    readonly allowKeepOnSubjectRevocation: boolean;
}
/**
 * The `federationGrantPolicy` a composition holds, as a frozen copy: each
 * member read from `value` exactly once and held to its contract rule, so
 * what was checked is what is answered and a later change to `value` changes
 * nothing a reader holds. Members no reader reads are not carried.
 *
 * A reader calls it on the slot it is handed before reading a member; a
 * reader handed no slot has grants off and calls nothing.
 *
 * @throws RangeError naming the first member that is missing, not a boolean
 *   or whose read throws; an `allowKeepOnSubjectRevocation` of `true` beside
 *   an `enabled` of `false`; or the slot when it holds no policy object.
 */
export declare function checkFederationGrantPolicy(value: unknown): FederationGrantPolicy;
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        /**
         * The federation grants' switch and keep policy, provided by the module
         * that owns `federation-grants {}`; absent, grants are off. Not core's
         * `grantPolicy`, the gate token-minting paths consult (allow or deny,
         * optionally narrowing the scope and audience).
         */
        readonly federationGrantPolicy?: FederationGrantPolicy;
    }
}
//# sourceMappingURL=policy.d.mts.map