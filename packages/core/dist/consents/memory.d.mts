import type { ConsentStore, PendingConsentStore } from "./types.mjs";
/** In-process consent store, with the record count exposed for observability. */
export interface MemoryConsentStore extends ConsentStore {
    /** Records currently resident, expired-but-unswept included. */
    readonly size: number;
}
/**
 * In-process Map-backed {@link ConsentStore} (#527).
 *
 * Bounded by population: one record per (`sub`, `clientId`), so it grows with
 * users × clients and never with time — unlike a jti denylist there is
 * nothing here that only expiry can reclaim. An expired record is dropped
 * when it is next read; `grant` overwrites in place.
 *
 * Single-replica only. Consent forks per replica: a "yes" recorded on one
 * replica is asked for again on every other, which is why the module that
 * provides this declares itself replica-unsafe and `deployment.mode = "multi"`
 * refuses it by name.
 */
export declare function createMemoryConsentStore(): MemoryConsentStore;
/** In-process pending-consent store, with the record count exposed for observability. */
export interface MemoryPendingConsentStore extends PendingConsentStore {
    /** Records currently resident, expired-but-unswept included. */
    readonly size: number;
}
/**
 * How many requests one session may have parked at once (#527 audit).
 *
 * Records are keyed by challenge and reclaimed only on expiry, so without a
 * bound one authenticated session could park an unbounded number inside the
 * ten-minute window. A browser has no use for more than a handful of consent
 * pages open at once; past the bound the oldest of that session's requests
 * goes, and every other session is untouched.
 */
export declare const PENDING_CONSENT_PER_SESSION_LIMIT = 16;
/**
 * In-process Map-backed {@link PendingConsentStore} (#552).
 *
 * `consume` reads and deletes with no `await` between them, which in a
 * single-threaded process is the atomic step the port asks for. Bounded by
 * traffic rather than population — one record per parked request, gone when
 * answered or expired — so an expired record is dropped when it is next
 * touched, and the whole map is swept when it has grown past a floor and
 * doubled since, which keeps abandoned pages from accumulating without a
 * timer of our own.
 *
 * Single-replica only, for the same reason as the consent store it is
 * provided with: a challenge parked on one replica is unknown to every other.
 */
export declare function createMemoryPendingConsentStore(): MemoryPendingConsentStore;
//# sourceMappingURL=memory.d.mts.map