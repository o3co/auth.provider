import type { FederationGrantStore } from "./store.mjs";
/** How long a record outlives its expiry, so that the status route can still answer for it (D16). */
export declare const DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS: number;
/**
 * Sweep once the store holds this many records, and then again each time it
 * has doubled: a connect the user never finishes leaves a `pending` record
 * nobody reads again, under an ID nobody lodges again, and reclaiming on touch
 * alone would keep every one of them. Amortized, with no timer of its own, as
 * the pending-consent store does.
 */
export declare const MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR = 1024;
export interface MemoryFederationGrantStoreOptions {
    /**
     * Milliseconds a record is retained past its expiry — or, for a grant
     * revoked while `pending`, past its revocation. Default
     * {@link DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS}. A credential gets
     * none: it is never disclosed from the expiry on, and it is dropped by
     * whatever touches the record next once this process's clock has passed it.
     */
    readonly tombstoneRetentionMs?: number;
}
/** In-process grant store, with what is resident exposed for observability. */
export interface MemoryFederationGrantStore extends FederationGrantStore {
    /** Records currently resident, reclaimable-but-unreclaimed included. */
    readonly size: number;
    /**
     * Whether a credential is resident for the grant. Through the port a grant
     * that is not `active` reads as `absent` whether its secret was deleted or is
     * only hidden; this is what tells the two apart. Touches nothing.
     */
    holdsCredential(grantId: string): boolean;
}
/**
 * In-process Map-backed {@link FederationGrantStore} (#593, D16).
 *
 * Every write checks and applies with no `await` in between, which on one
 * thread is the atomic step the port asks for. Nothing is sealed: the
 * credentials sit in a Map beside the record, so `unreadable` and
 * `key_unavailable` are states this adapter never reports. What it does keep
 * is everything the contract says about them — one snapshot per `open`, no
 * credential outside `active`, none past the expiry.
 *
 * Two clocks, kept apart as a store with key TTLs keeps them. What a caller is
 * told is judged on the `now` it passes. What is reclaimed — a record nothing
 * can read any more, a credential whose grant has expired — is judged on this
 * process's own clock, whenever an operation touches the record and when a
 * lodging sweeps. So a `now` that is wrong for one call is told the wrong
 * thing once, and costs nothing: the next call finds the record where it was.
 * A listing scans the store, which is what a development adapter can afford.
 *
 * Single-replica only. Grants fork per replica: one lodged, revoked or
 * refreshed on one replica is unknown, still usable or stale on every other,
 * which is why the module that provides this declares itself replica-unsafe
 * and `deployment.mode = "multi"` refuses it by name.
 */
export declare function createMemoryFederationGrantStore(options?: MemoryFederationGrantStoreOptions): MemoryFederationGrantStore;
//# sourceMappingURL=memory.d.mts.map