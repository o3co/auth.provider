import { type AmortizedSweepOptions } from "../single-use/sweep.mjs";
import { type MfaTransactionStore } from "./transactionStore.mjs";
/** Writing `create` calls between two sweeps of expired transactions. */
export declare const DEFAULT_MEMORY_MFA_TRANSACTION_STORE_SWEEP_INTERVAL = 1000;
/** The least time between two sweeps, in milliseconds. */
export declare const DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MIN_SWEEP_INTERVAL_MS = 10000;
/**
 * The default cap, on transactions, session email proofs and first-binding
 * marks together. A
 * transaction carries the login's `User` snapshot, so the cap is lower than
 * the challenge and `jti` stores'. Over the ten-minute default lifetime it
 * allows about 170 new transactions a second on one replica, more password
 * logins than one process verifies.
 */
export declare const DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES = 100000;
export interface MemoryMfaTransactionStoreOptions extends AmortizedSweepOptions {
    /** The clock a transaction expires by, in epoch milliseconds. Default `Date.now`. */
    readonly now?: () => number;
    /**
     * The most entries held — transactions, session email proofs,
     * first-binding marks, subject leases and recovery authorizations,
     * expired-but-unswept included; default
     * {@link DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES}. Anything but a
     * positive whole number up to 2^24 (a `Map`'s limit) is a `RangeError`,
     * never read as no cap.
     */
    readonly maxEntries?: number;
}
/**
 * Thrown by `create` at the cap when nothing has expired. A store fault, like a
 * Redis write refused at `maxmemory`, not a `RangeError` (which a caller reads
 * as its own mistake); the MFA routes answer `503 temporarily_unavailable`.
 * `reason` survives in a logged projection.
 */
export declare class MfaTransactionStoreFullError extends Error {
    readonly reason: "full";
    constructor(maxEntries: number);
}
/** In-process transaction store, with what is resident exposed for observability. */
export interface MemoryMfaTransactionStore extends MfaTransactionStore {
    /** Transactions resident, expired-but-unswept included. */
    readonly transactions: number;
    /** Bindings holding a resident transaction. */
    readonly bindings: number;
    /** Subjects with lock state resident. */
    readonly subjects: number;
    /** Session email proofs resident, expired-but-unswept included. */
    readonly sessionEmailProofs: number;
    /** First-binding marks resident, expired-but-unswept included. */
    readonly firstBindingMarks: number;
    /** Subject leases resident, expired-but-unswept included. */
    readonly subjectLeases: number;
    /** The most entries it holds (`maxEntries`), transactions, proofs, marks, leases and authorizations together; at it, a new one is refused. */
    readonly maxEntries: number;
}
export declare function createMemoryMfaTransactionStore(options?: MemoryMfaTransactionStoreOptions): MemoryMfaTransactionStore;
//# sourceMappingURL=memoryTransactionStore.d.mts.map