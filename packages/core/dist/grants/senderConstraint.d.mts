/**
 * Per-client sender-constraint requirement. See Wave 2 Token-binding
 * Cluster spec §4.8.
 *
 * When `required: true` and no binding is presented, the request is
 * rejected `invalid_client`. When `required: true` and a binding is
 * presented whose `kind` is not in `methods`, the request is rejected
 * `unauthorized_client`. When `required: false`, `methods` is advisory
 * (no rejection occurs based on it).
 */
export interface SenderConstraint {
    readonly required: boolean;
    readonly methods: readonly string[];
}
//# sourceMappingURL=senderConstraint.d.mts.map