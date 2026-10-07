import type { FederationGrantLockResult } from "@o3co/auth-provider-core";
/** What the lock needs from a connection: take it if nobody holds it, and free the one this caller holds. */
export interface FederationGrantLockClient {
    /** `SET key token NX PX ttl`: whether this caller now holds it. */
    tryLock(lockKey: string, token: string, ttlMs: number): Promise<boolean>;
    /** Deletes the key only while its value is still `token`. */
    unlock(lockKey: string, token: string): Promise<void>;
}
export interface FederationGrantLockOptions {
    readonly client: FederationGrantLockClient;
    readonly lockKey: (grantId: string) => string;
    /** How long to leave between attempts. Default 25 ms. */
    readonly pollIntervalMs?: number;
    /**
     * The monotonic clock, in milliseconds. Default `performance.now`.
     *
     * A seam, and only for tests: what `waitedMs` rounds to, and which side of
     * the deadline an attempt falls on, are differences of one millisecond that
     * no test can produce on a real clock reliably — and the direction of the
     * rounding is the difference between a lease that is understated and one
     * that is overstated.
     */
    readonly now?: () => number;
}
/**
 * The lock a refresh holds (#593, D12), over a connection.
 *
 * ## What `waitedMs` is, and why it is measured where it is
 *
 * The lease is spent from the moment the store took the lock, and the
 * acknowledgement's own travel is spent too: core dates the lease at
 * `askedAt + waitedMs` and measures the rest itself. So `waitedMs` is the
 * elapsed time recorded **immediately before the attempt that succeeded was
 * sent** — a conservative lower bound on when the lease began. Including the
 * answer's travel would put the lease later than it started, which is the one
 * direction that is unsafe: two refreshes would present one refresh token.
 *
 * It is measured on `performance.now()` and not on `Date.now()`, which steps
 * when the host's clock is set — a wait reported as negative, or as hours,
 * and core refusing the lease of a lock that was in fact taken at once.
 *
 * ## What it does not do
 *
 * It does not give back a lock it took because the answer was late. That
 * would say `timeout`, which means another holder has it, and core turns that
 * into "serve what is stored, come back later" — so a grant nothing was
 * competing for would go unrefreshed. Core already measures the
 * acknowledgement and refuses to start upstream work once the budget is
 * spent; that decision belongs there, with the whole call in view.
 *
 * It does not retry an attempt whose answer never came. A lock that may or
 * may not have been taken must not be taken again: the TTL is what frees it.
 */
export declare function createFederationGrantLock(options: FederationGrantLockOptions): {
    acquire(grantId: string, bounds: {
        readonly ttlMs: number;
        readonly waitForMs: number;
    }): Promise<FederationGrantLockResult>;
};
//# sourceMappingURL=federation-grant-lock.d.mts.map