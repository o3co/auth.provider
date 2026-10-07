/**
 * SF-13 — what an upstream federation refresh failed with.
 *
 * - `invalid_grant`: the IdP rejected the refresh token (revoked, expired,
 *   mismatched).
 * - `rate_limited`: the IdP answered 429.
 * - `network`: an upstream 5xx, a connection refused or timed out, a DNS
 *   failure.
 * - `unknown`: anything else.
 */
export type FederationRefreshErrorReason = "invalid_grant" | "rate_limited" | "network" | "unknown";
export interface FederationRefreshErrorClassification {
    readonly reason: FederationRefreshErrorReason;
    /**
     * Whether `reason` was read off the error's structured properties, and not
     * matched in its message. The message fallback is a guess: the session-bound
     * route acts on it, as it always has, because there a wrong guess costs one
     * session its upstream tokens. A federation grant does not (#593, D12): a
     * wrong `invalid_grant` there would send a user through consent again for
     * nothing, so only a structured one ends its credentials.
     */
    readonly structured: boolean;
    /**
     * The upstream's error code, when it is one this provider knows. Never a
     * message, and never an unknown string: a caller may put this in a response.
     */
    readonly upstreamCode?: string;
    /** Whole seconds, from the response's `Retry-After`, when it named a usable number. */
    readonly retryAfterSeconds?: number;
}
/**
 * The error codes this provider repeats. An allow-list, and not a pattern: any
 * pattern that fits `invalid_client` fits an opaque token as well, and an
 * upstream that echoes what it was sent must not get a refresh token repeated
 * through this field. Anything else an upstream sends is left out, and a
 * caller reports it as unknown.
 */
export declare const KNOWN_ERROR_CODES: ReadonlySet<string>;
/**
 * Classifies what an upstream refresh rejected with. Structured properties
 * (`.error`, `.status`, `.code`) are preferred over message matching; the
 * message fallback is defense-in-depth for legacy or non-openid-client errors,
 * and `structured` says which of the two answered.
 *
 * Moved here from the session-bound token route, whose behaviour is unchanged:
 * it acts on `reason` alone. The federation grant retrieval (#593, D12) is the
 * second caller.
 */
/**
 * Whether a code may be repeated to a caller (#593, D11, D18).
 *
 * The allow-list above is applied where a classification is *made*, and a
 * stamped code is read back where one is *remembered* (D12) — a stamp a
 * fixture seeded, a version wrote before this list, or someone edited in the
 * keyspace would otherwise reach a caller unchecked. So the same question is
 * asked again wherever a reason is built from stored data, which is what keeps
 * D11's promise true rather than merely intended.
 */
export declare function isKnownFederationRefreshErrorCode(code: unknown): code is string;
export declare function classifyFederationRefreshError(error: unknown): FederationRefreshErrorClassification;
//# sourceMappingURL=refresh-error.d.mts.map