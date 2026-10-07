/** The named ranges, for operator-facing error messages and documentation. */
export declare const TRUSTED_PROXY_NAMED_RANGES: readonly string[];
/** Why a trusted-proxy entry is unusable, phrased for a boot-time message. */
export type TrustedProxyEntryRejection = "not-a-string" | "empty" | "not-an-address-or-keyword" | "bad-prefix-length" | "netmask-notation";
/**
 * Returns `null` when `value` is a usable trusted-proxy entry, otherwise the
 * reason it is not.
 *
 * Mirrors the `checkCanonicalIssuer` / `describeIssuerRejection` pair in
 * `../issuer/canonical.mjs`: the check is reusable from a Zod `superRefine`
 * (which needs the reason to build a per-index issue) and from a plain
 * `throw` site (which needs the sentence).
 */
export declare function checkTrustedProxyEntry(value: unknown): TrustedProxyEntryRejection | null;
/** Whether `value` is a usable trusted-proxy entry. */
export declare function isTrustedProxyEntry(value: unknown): value is string;
/** Operator-facing explanation for each rejection reason. */
export declare function describeTrustedProxyEntryRejection(reason: TrustedProxyEntryRejection): string;
/** Options for {@link createTrustedProxyMatcher}. */
export interface TrustedProxyMatcherOptions {
    /**
     * Config key named in a boot-time error, so the operator is pointed at the
     * setting they wrote rather than at this function. Defaults to
     * `"trusted-proxies"`.
     */
    readonly label?: string;
}
/**
 * Build a predicate answering whether an observed peer address is one of the
 * configured trusted proxies.
 *
 * **Feed it the peer address, never `req.ip`.** `req.ip` is derived from
 * `X-Forwarded-For` whenever Express `trust proxy` is on, so authenticating a
 * forwarding hop with it would be authenticating one header with another and
 * would make the allowlist decorative. The only thing on an HTTP request an
 * attacker cannot choose is the address of the peer that opened the TCP
 * connection — `req.socket.remoteAddress`.
 *
 * An IPv4 entry (literal or range) also matches the IPv4-mapped IPv6 form
 * (`::ffff:10.0.0.7`) Node reports on a dual-stack listener, so operators do
 * not have to know which family the listener bound.
 *
 * An empty list produces a predicate that trusts nothing. That is the correct
 * fail-closed behaviour: callers that require a non-empty allowlist enforce it
 * at boot with an operator-facing message, and this layer must not be the thing
 * that decides an unconfigured deployment is safe.
 *
 * Throws at construction on an unusable entry — see
 * {@link checkTrustedProxyEntry}. A hostname or a typo would otherwise never
 * match and turn a deliberate allowlist into a silent outage.
 */
export declare const createTrustedProxyMatcher: (entries: readonly string[], options?: TrustedProxyMatcherOptions) => ((remoteAddress: string | undefined) => boolean);
//# sourceMappingURL=trusted-proxy.d.mts.map