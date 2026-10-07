/**
 * Whether a client's `allowedGrantTypes` permits `grantType`.
 *
 * This is the **central** rule, applied once at grant dispatch and at
 * `/authorize` so every current and future grant inherits it (#268).
 *
 *   - `undefined` (no allowlist declared) → allowed. Absence means
 *     "unrestricted", not "denied": the field post-dates the grants that
 *     ignore it, so treating absence as denial would revoke every grant from
 *     every registration written before it existed — a total outage on
 *     upgrade rather than a security fix.
 *   - declared → allowed iff `grantType` appears in it. An empty array
 *     therefore denies everything, which is what "this client may use no
 *     grant type" has always meant for this field.
 *
 * A grant MAY declare a stricter rule via
 * `GrantHandler.requiresExplicitGrantAllowlist` (#326): dispatch then denies
 * by absence for that grant — deliberately, so that machine-to-machine
 * access is never acquired by omission. `client_credentials` and the
 * WebAuthn grant declare it. The two rules compose to the stricter of the
 * pair, because either can reject and only the absent case distinguishes
 * them; both are enforced at dispatch, next to each other.
 *
 * Exact string comparison: `grant_type` is case-sensitive, and extension
 * grants are URIs (RFC 6749 §4.5), where a prefix or case-folded match would
 * be a namespace confusion rather than a convenience.
 */
export declare const isGrantTypeAllowed: (allowedGrantTypes: readonly string[] | undefined, grantType: string) => boolean;
//# sourceMappingURL=allowedGrantTypes.d.mts.map