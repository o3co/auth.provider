/**
 * The write lifetime W of a store's bounded writes: its conditional writes
 * (docs/adapter-surface.md, "Conditional writes", rule 6) and any unconditional
 * write it bounds the same way, such as the federation token store's `attach`.
 * The adapter stamps each write with a deadline, its issue time plus
 * {@link WRITE_TIMEOUT_MS} on the app's clock; the write's script refuses it at
 * or after that deadline on the server's clock, writing nothing; and the
 * adapter stops waiting at the same timeout. A command the driver queues,
 * sends again after a reconnect, or a stalled server holds therefore commits
 * within W of its issue or writes nothing, while the app's and Redis's clocks
 * agree within {@link CLOCK_SKEW_MS}, and the server does not stall inside a
 * running script, between its clock check and its write, for the whole of W.
 */
/**
 * How far past its issue a write's deadline lies, and how long the adapter
 * waits for its answer. It matches the 1 000 ms `commandTimeout` the README
 * asks of the connection.
 */
export declare const WRITE_TIMEOUT_MS = 1000;
/**
 * The clock skew allowed between the app, which sets a deadline, and the
 * Redis server, which judges it: the 1 s the operator runbook asks of every
 * replica's clock ("Replica clocks").
 */
export declare const CLOCK_SKEW_MS = 1000;
/** W: a bounded write, conditional or not, commits or fails within this of its issue. */
export declare const WRITE_LIFETIME_MS: number;
/**
 * `write` run with its deadline, {@link WRITE_TIMEOUT_MS} from now, and its
 * answer awaited no longer than that: past it, the wait ends in
 * `unanswered()`, whose outcome is unknown (the write may have committed, or
 * may still commit within W).
 */
export declare function withWriteDeadline<T>(write: (deadlineMs: number) => Promise<T>, unanswered: () => Error): Promise<T>;
//# sourceMappingURL=write-deadline.d.mts.map