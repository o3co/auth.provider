import type { FederationGrantStore } from "./store.mjs";
import { type FederationGrantConnection, type FederationGrantTokenResult } from "./types.mjs";
/**
 * What a delegated refresh answers (#593, D17), as far as the retrieval needs
 * it. Structural, as the session-bound route's refresh shape is, so that core
 * does not depend on the package the adapters live in.
 *
 * Every field is optional, as the adapters' own token snapshot has them, and
 * none is trusted: the retrieval reads an answer field by field, keeps the
 * refresh token it came with whatever else is wrong, and treats an answer it
 * cannot use as `malformed_token_response`.
 */
export interface FederationGrantRefreshedToken {
    readonly accessToken?: string;
    /** Absent when the upstream did not rotate it (RFC 6749 §6): the stored one is kept. */
    readonly refreshToken?: string;
    /**
     * Seconds, exactly as the upstream issued them; `null` when it named none.
     * This is what eligibility judges. It cannot be recovered from `expiresAt`:
     * one step of the clock between the adapter and here turns 3600 into 3601,
     * and starves every grant on a connection whose maximum is 3600.
     */
    readonly expiresIn?: number | null;
    /**
     * The adapter's own `now + expiresIn`. With `expiresIn` it anchors when the
     * token was obtained on the ADAPTER's reading of the clock; pairing
     * `expiresIn` with a later reading taken here would extend the expiry.
     */
    readonly expiresAt?: Date | null;
    /** Space-delimited, as in the token response. Absent means "as the grant's" (RFC 6749 §6). */
    readonly scope?: string;
    readonly tokenType?: string;
}
export interface FederationGrantRefresher {
    refreshDelegatedToken(params: {
        readonly refreshToken: string;
        readonly scopes?: readonly string[];
        readonly resource?: string;
        readonly signal?: AbortSignal;
    }): Promise<FederationGrantRefreshedToken>;
}
/** Token-free, always: no event carries an access token, a refresh token, or any other secret (D18). */
export interface FederationGrantAuditEvent {
    readonly type: "federation.grant.token.success" | "federation.grant.token.denied" | "federation.grant.refreshed" | "federation.grant.refresh_failed" | "federation.grant.refresh_persist_failed" | "federation.grant.reauthorization_required" | "federation.grant.revoked"
    /**
     * A withdrawal that did not happen (D18). Its own type rather than a
     * `.token.denied` with a different outcome: a dashboard counting
     * denied disclosures would otherwise count refused withdrawals with
     * them, and the two mean opposite things — one is a credential not
     * handed out, the other is a credential still live that somebody tried
     * to end.
     */
     | "federation.grant.revoke.denied"
    /** Slice 6: a client lodged an intent — a first grant, or a renewal (D6). */
     | "federation.grant.requested"
    /**
     * Slice 6: a lodging that did not happen. Its own type, for the reason
     * `.revoke.denied` is: a refused request to CREATE access is not a
     * refused disclosure of access that exists.
     */
     | "federation.grant.request.denied"
    /**
     * Slice 6: a connect flow that ended without a grant — the user
     * declined, the session was not the right one, the flow went stale.
     * Only facts established by then are carried: an early failure may
     * have no grant id to name (D18 amended).
     */
     | "federation.grant.authorization_failed"
    /** Slice 6: a connect flow created a grant (D7 check 8 won). */
     | "federation.grant.authorized"
    /** Slice 6: a renewal replaced a grant's authorization in place. */
     | "federation.grant.reauthorized";
    readonly correlationId: string;
    readonly grantId: string;
    /** The caller. */
    readonly clientId: string;
    /** The owner the caller asserted; for a grant that is the caller's, the grant's. */
    readonly subject: string;
    /** Absent for a grant that is unknown to the caller, and for one never authorized. */
    readonly upstream?: {
        readonly issuer: string;
        readonly subject: string;
    };
    readonly connection?: string;
    readonly resource?: string;
    readonly scopes?: readonly string[];
    /** `success`, a denial's `code` or `code/reason`, or what a refresh ended with. */
    readonly outcome: string;
}
export interface FederationGrantRetrievalLimits {
    /** `federationGrants.maxExpiresIn`, as it is configured now. */
    readonly maxExpiresInMs: number;
    /**
     * How far replicas' clocks may differ. It is the backstop's allowance (D13),
     * and how far ahead of `now` a stored token may be dated and still be
     * believed.
     */
    readonly revocationSkewMs: number;
    /**
     * A stored token with no more life left than this is refreshed (30 s) —
     * unless it is not yet half spent, which a token issued with less than twice
     * this may be, or the grant's marker says the upstream is not to be asked
     * yet: then it is answered with the life it has.
     */
    readonly refreshBufferMs: number;
    readonly ineligibleRetryAfterMs: number;
    /**
     * How long the upstream is not asked again after it failed twice in a row
     * (30 s), and the least a rate limit is honoured for (D12). The first
     * failure of a row is retried promptly. `ineligibleRetryAfterMs` is the
     * ceiling, and what a refusal with a code this provider knows waits.
     */
    readonly refreshFailureBackoffMs: number;
    /** The SOFT deadline: how long a caller waits for the upstream (D12). */
    readonly upstreamTimeoutMs: number;
    /** The HARD deadline: where the upstream request is aborted. */
    readonly upstreamHardTimeoutMs: number;
    readonly refreshLockTtlMs: number;
    /**
     * How long a call waits for another replica's refresh before it looks again
     * and answers. Nothing relates it to `refreshLockTtlMs`: after an outcome
     * that is unknown the lock is left to run out, and until it has, every call
     * that needs a refresh answers `lock_timeout` after waiting this long.
     */
    readonly lockWaitMs: number;
    readonly persistRetryBudgetMs: number;
}
/**
 * What a refresh that keeps to its deadlines must still leave of its lock. The
 * lease is counted from when the lock was asked for plus what the store says
 * it waited — a lower bound on when the TTL began, since the store took the
 * lock some time after the caller asked — and timers fire late. Without a
 * margin, a configuration that fits by a millisecond does not fit.
 */
export declare const FEDERATION_GRANT_REFRESH_LOCK_MARGIN_MS = 1000;
/** What went wrong where a cause is otherwise swallowed into a typed answer. For a logger; never for a response. */
export interface FederationGrantRetrievalFailure {
    readonly during: "boundary" | "open" | "status" | "backstop_revoke" | "lock" | "release" | "upstream" | "mark" | "write" | "touch" | "audit" | "background" | "refresh";
    readonly error: unknown;
    readonly grantId: string;
    readonly correlationId: string;
}
export interface RetrieveFederationGrantTokenDeps {
    readonly store: FederationGrantStore;
    /** The connection as it is configured now; `undefined` when the operator removed it. */
    connection(name: string): FederationGrantConnection | undefined;
    refresher(connection: FederationGrantConnection): FederationGrantRefresher | undefined;
    /**
     * The subject's grants boundary (D13). A failure fails closed: 503. Neither
     * this read nor the store's `open` is bounded by the retrieval: a reader
     * that can hang carries its own timeout. What the retrieval bounds is the
     * wait for the refresh lock, and everything that holds it.
     */
    grantsBoundary(subject: string): Promise<Date | null>;
    /** Sampled at every write and before every disclosure, never once per request. */
    now(): Date;
    readonly limits: FederationGrantRetrievalLimits;
    /**
     * The one seam for work that may outlive a call's answer, so that a shutdown
     * can drain it and a test can await it; nothing is detached any other way.
     * That is the tail of every refresh — letting go of the lock, then telling
     * the audit sink — and, when the caller stopped waiting at the soft
     * deadline, the refresh itself, which goes on holding the lock until its
     * result is persisted (D12); and the record of a use and the audit of an
     * answer, neither of which an answer waits for. The promise never rejects.
     */
    background(work: Promise<void>): void;
    /**
     * A sink that throws, rejects or never answers skips no write, holds no
     * lock and delays no answer: it is told after the lock is let go of, and
     * nothing waits for it.
     */
    audit?(event: FederationGrantAuditEvent): void | Promise<void>;
    /**
     * Told the cause wherever one is turned into a typed answer, or dropped:
     * a 503 says that something failed, and an operator needs to know what. The
     * error may be an upstream's, and may carry what the upstream echoed: it is
     * for a logger that redacts, and never for a response.
     */
    report?(failure: FederationGrantRetrievalFailure): void;
}
export interface RetrieveFederationGrantTokenRequest {
    readonly grantId: string;
    /** The authenticated client. */
    readonly clientId: string;
    /** `sub`, required on every grant-addressed route (D9). */
    readonly subject: string;
    /** The client's `allowedFederationGrantConnections`. */
    readonly allowedConnections: readonly string[];
    readonly correlationId: string;
    readonly connection?: string;
    readonly scope?: readonly string[];
    readonly resource?: string;
    readonly minTtlSeconds?: number;
}
/**
 * Refuses limits the retrieval cannot keep its promises under. For whoever
 * composes it to call at boot: a schema guarantees these, and a hand-built
 * config bypasses a schema (#448).
 *
 * - Every limit is a finite number, and none is negative; the ones a timer or
 *   a lock is given are positive, and fit a timer. NaN compares as fine
 *   everywhere: under a NaN refresh buffer no token is refreshed before it
 *   has died, and a NaN retry interval switches the marker's limit off.
 * - `refreshFailureBackoffMs <= ineligibleRetryAfterMs`: the marker's interval
 *   is the ceiling on how long a failing upstream is not asked (D12).
 * - `upstreamTimeoutMs <= upstreamHardTimeoutMs`: the soft deadline only
 *   answers the caller, and the hard one is where the request is aborted.
 * - `upstreamHardTimeoutMs + persistRetryBudgetMs + margin <= refreshLockTtlMs`
 *   (D12). The lock has no renewal, and one that expires mid-refresh lets two
 *   replicas present the same refresh token.
 *
 * This compares configured durations and nothing else. What makes them mean
 * something is in the retrieval: every deadline counts from the moment the
 * lock was acquired, and the upstream is not asked at all once the look under
 * the lock has used up the time a caller waits.
 */
export declare function assertFederationGrantRetrievalLimits(limits: FederationGrantRetrievalLimits): void;
/**
 * An upstream access token for a federation grant (#593, D10–D12): every
 * retrieval re-evaluates the grant, a call refreshes at most once, and a
 * writer that loses never returns the token it fetched. The package maps the
 * typed result to HTTP and does nothing else.
 *
 * It answers with a typed result for everything its dependencies may do at
 * run time — reject, throw, answer late or answer nonsense. It rejects only
 * for a bug in how it was composed: a `connection`, `refresher` or `now` that
 * throws. Even then no lock is left behind.
 */
export declare function retrieveFederationGrantToken(deps: RetrieveFederationGrantTokenDeps, request: RetrieveFederationGrantTokenRequest): Promise<FederationGrantTokenResult>;
//# sourceMappingURL=retrieve.d.mts.map