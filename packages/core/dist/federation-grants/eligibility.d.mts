import type { FederationGrantConnection, FederationGrantIneligibilityMarker, FederationGrantIneligibilityReason, FederationGrantRefreshFailure, FederationGrantRefreshFailureKind } from "./types.mjs";
/**
 * Whether every name in `scopes` is in `within`. Exact, on the names the
 * connection configures: an adapter whose IdP answers in another vocabulary
 * normalizes before it reports, or its connections fail closed (#593, D7).
 */
export declare function scopesWithin(scopes: readonly string[], within: readonly string[]): boolean;
/**
 * Whether a connection's `maxAccessTokenLifetime` is a maximum at all: a
 * positive, finite number of seconds. A schema guarantees that, and a
 * hand-built config bypasses a schema (#448).
 *
 * Infinity is not one. Every finite lifetime is within it, so residual access
 * (D15) would be a number nobody chose; admitting unbounded tokens is an
 * opt-in the ADR leaves for later (D5). Under a maximum that is not usable no
 * token is eligible, and the three rules below all say so.
 */
export declare function isUsableMaxUpstreamAccessTokenLifetime(maxAccessTokenLifetime: number): boolean;
export type UpstreamTokenJudgement = {
    readonly eligible: true;
} | {
    readonly eligible: false;
    readonly reason: FederationGrantIneligibilityReason;
};
/**
 * Whether an upstream access token may be disclosed (#593, D5).
 *
 * It guards every disclosure, cached or fresh, against the connection's
 * CURRENT `maxAccessTokenLifetime` — so lowering that takes effect on the next
 * call, and not when a cached token happens to run out.
 *
 * - The lifetime must be finite. A provider cannot shorten what a token it
 *   already handed out still allows, so a token with no expiry would make
 *   residual access unbounded.
 * - It must not exceed the maximum. "Finite" alone would admit a 30-day token;
 *   the maximum is what turns residual access into a number the operator chose.
 *   The lifetime judged is the one the token was ISSUED with, not what remains
 *   of it, so a token does not become disclosable by ageing.
 * - The scopes it carries must be within what the user consented to. An IdP
 *   that accumulates consent answers a refresh with every scope the user has
 *   since granted to the same upstream client, and an upstream token cannot be
 *   narrowed after the fact.
 * - It must be a bearer token, however the upstream spells it (oauth4webapi
 *   lower-cases what it was sent). A sender-constrained token — DPoP, or any
 *   other — is bound to a key the client that receives it does not hold: the
 *   route has no proof key to present, and disclosing such a token as a
 *   bearer token would hand out something that cannot be used.
 *
 * A maximum that is not usable refuses every token. It is tested by name, and
 * not left to the comparison: a hand-built config that omits the key hands
 * `undefined` through a cast, every comparison with `undefined` or NaN is
 * false, and "is it over?" would answer no for a 30-day token — while
 * Infinity compares well and admits all of them.
 */
export declare function judgeUpstreamAccessToken(token: {
    /** Seconds, as issued; `null` when the upstream named no finite lifetime. */
    readonly issuedLifetime: number | null;
    readonly scopes: readonly string[];
    readonly consentedScopes: readonly string[];
    /** Seconds. */
    readonly maxAccessTokenLifetime: number;
    /** As the upstream answered it; compared without regard to case. */
    readonly tokenType: string;
}): UpstreamTokenJudgement;
/**
 * Whether a marker still says the grant's last refresh brought no token that
 * could be disclosed. This is what the status route reports (D5, D9): it never
 * calls a grant `active` that cannot be refreshed into a usable token. The
 * converse does not hold: `/token` goes on answering the token the grant had,
 * while that one lasts, under a marker that stands.
 *
 * Three things clear a marker: an eligible refresh, a reauthorization, and a
 * change to the maximum it was judged against — the operator fixing the
 * setting must not have to wait. Time is not one of them. The retry interval
 * below limits how often `/token` tries again; it says nothing about whether
 * the next try will succeed.
 *
 * A change to a maximum that is not usable is no fix: every token is refused
 * under it, so the marker stands. Comparing alone would void it — and a marker
 * judged against NaN would never stand at all, `NaN === NaN` being false,
 * which puts back the refresh on every call the marker exists to prevent.
 */
export declare function federationGrantIneligibilityStands(marker: FederationGrantIneligibilityMarker | undefined, 
/** Seconds; the connection's current value. */
maxAccessTokenLifetime: number): boolean;
/**
 * Whether `/token` may call the upstream again for a grant whose marker
 * stands. Without the interval a starved grant would take the lock, call the
 * upstream and rotate the refresh token on every request — each rotation
 * another chance to lose the credential, and a drain on an upstream rate limit
 * that other grants share.
 *
 * The marker is outside the authenticated envelope, so whoever can write the
 * record can date it in the future. One dated further ahead than `allowanceMs`
 * — what replicas' clocks may differ by, and the refresh buffer absorbs — is
 * not believed, and a retry is due: clamping only what the client is TOLD
 * would leave such a marker standing until its date caught up. The wait is
 * rounded up, so a client is never told to retry in zero seconds, and never
 * longer than the interval. When the arithmetic is not a number a retry is
 * due. That is the safe direction here, because `judgeUpstreamAccessToken`
 * still guards what is disclosed.
 */
export declare function federationGrantIneligibilityRetry(marker: FederationGrantIneligibilityMarker | undefined, context: {
    readonly now: Date;
    readonly retryAfterMs: number;
    readonly allowanceMs: number;
}): {
    readonly due: true;
} | {
    readonly due: false;
    readonly retryAfterSeconds: number;
};
/**
 * The codes an IdP answers a refresh with when it wants the user, and not a
 * new token (OIDC Core §3.1.2.6, echoed by RFC 6749 §5.2 token endpoints):
 * conditional access changed under a paused job, a consent was withdrawn, a
 * session policy demands a fresh sign-in. None of them says the refresh token
 * is bad — the next refresh after the user returns may well succeed — so the
 * credential is kept, and none of them is mended by waiting.
 */
export declare const FEDERATION_GRANT_INTERACTION_CODES: readonly ["interaction_required", "login_required", "consent_required", "account_selection_required"];
export type FederationGrantInteractionCode = (typeof FEDERATION_GRANT_INTERACTION_CODES)[number];
/**
 * What a stamp remembers when a refresh was refused for the user's absence
 * (#616, D11, D12): the code, when the stamp is a refusal carrying one of the
 * four, and `undefined` for every other stamp — an outage or a rate limit that
 * happens to carry the same string is not the user being asked for. A stamp
 * that answers here reads as `reauthorization_required` for as long as it
 * stands, whatever its date, its count or its retry advice say: those are the
 * timed backoff's, and time mends nothing here.
 */
export declare function federationGrantInteractionCode(failure: FederationGrantRefreshFailure | undefined): FederationGrantInteractionCode | undefined;
/** Whether an upstream's error code — one the classifier read off the error's own field — is one of the four. */
export declare function isFederationGrantInteractionCode(code: unknown): code is FederationGrantInteractionCode;
/**
 * Whether the stamp of a failed refresh (D12) still keeps `/token` from asking
 * the upstream, and for how long a client is told to wait. What the wait is
 * depends on what failed:
 *
 * - `unavailable` — nothing for the FIRST failure in a row: the request may
 *   have been processed and its answer lost, and an IdP that keeps a grace
 *   window for exactly that takes the old refresh token back on a prompt
 *   retry, not a late one. The next poll is that retry. From the second
 *   failure on, `backoffMs`.
 * - `rate_limited` — the upstream's advice, never less than `backoffMs` and
 *   never more than `ceilingMs`: a 429 was not processed, and there is
 *   nothing to recover promptly.
 * - `rejected` — `ceilingMs`: an error code this provider knows is a
 *   configuration fault, the marker's class of problem, and gets the marker's
 *   interval.
 *
 * A stamp dated further ahead than `allowanceMs` is not believed (as the
 * marker above), one that is not a date does not stand, and the wait a
 * client is told is rounded up and never longer than `ceilingMs`.
 */
export declare function federationGrantRefreshFailureStands(failure: FederationGrantRefreshFailure | undefined, context: {
    readonly now: Date;
    readonly allowanceMs: number;
    readonly backoffMs: number;
    readonly ceilingMs: number;
}): {
    readonly stands: false;
} | {
    readonly stands: true;
    readonly kind: FederationGrantRefreshFailureKind;
    readonly retryAfterSeconds: number;
};
export type FederationGrantIntentScopes = {
    readonly ok: true;
    readonly scopes: readonly string[];
} | {
    readonly ok: false;
    readonly reason: "outside_connection" | "required_scope_missing" | "subsets_not_allowed";
};
/**
 * The scopes an intent is lodged with (#593, D6): what consent will show and
 * what is requested upstream, in the order the connection lists them. The
 * connection's scopes are the ceiling.
 *
 * The result always keeps `openid`, because the adapter requires an id_token,
 * and `offline_access` where the connection lists it, because a grant without
 * a refresh credential is not one. That is one rule, applied to the set that
 * was resolved — whether the full set was asked for by name, by omission, or
 * forced by `allowScopeSubsets = false`, which a connection on an IdP that
 * accumulates consent sets (D19).
 */
export declare function resolveFederationGrantIntentScopes(requested: readonly string[] | undefined, connection: Pick<FederationGrantConnection, "scopes" | "allowScopeSubsets">): FederationGrantIntentScopes;
//# sourceMappingURL=eligibility.d.mts.map