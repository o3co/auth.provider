import type { GrantError, GrantPolicyContext, GrantPolicyDecision, GrantPolicyHook, GrantPolicyRequest } from "@o3co/auth-provider-core";
/**
 * The `allow` half of a {@link GrantPolicyDecision}, handed back so a caller
 * can read `grantedAudience` after the scope step has been applied.
 */
export type GrantPolicyAllow = Extract<GrantPolicyDecision, {
    outcome: "allow";
}>;
export type GrantPolicyOutcome = {
    readonly ok: true;
    readonly scopes: readonly string[];
    readonly decision: GrantPolicyAllow;
} | {
    readonly ok: false;
    readonly result: GrantError;
};
/**
 * Evaluate `grantPolicy` for a token grant, fail-closed (CP-18), and apply
 * its scope decision to the grant's already-narrowed effective scope.
 *
 * One home for the three rules every minting path applies, so the next grant
 * consults the policy by calling this rather than by knowing the folklore:
 *
 * - **A policy that throws is `503 temporarily_unavailable`**, never allow.
 *   Policy is a security boundary; failing open would grant the pre-policy
 *   ceiling, which is exactly what the policy exists to prevent.
 * - **`deny` is `400` with the policy's own error** and description.
 * - **`grantedScope` may only narrow.** It is re-validated against
 *   `effectiveScopes` — the request as already narrowed to every ceiling the
 *   grant knows — and not against a broader allowlist: a policy returning a
 *   scope the caller did not ask for is scope expansion even when the client
 *   would have been allowed it. An empty array is honoured as "strip all"
 *   (CP-15). Absent, the effective scopes stand.
 *
 * `grantedAudience` is left on `decision` for the caller: the audience ceiling
 * differs per grant (a client's `allowedAudiences`, a subject token's `aud`)
 * and this helper does not know which one applies.
 */
export declare function evaluateGrantPolicy(grantPolicy: GrantPolicyHook, request: GrantPolicyRequest, context: GrantPolicyContext, effectiveScopes: readonly string[]): Promise<GrantPolicyOutcome>;
//# sourceMappingURL=_grantPolicy.d.mts.map