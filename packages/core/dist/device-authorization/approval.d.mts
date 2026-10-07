import type { ApproveDeviceAuthorizationInput } from "./types.mjs";
/** An approval's authentication as a store records it. Absent stays absent. */
export interface RecordableDeviceApproval {
    /** A frozen copy of the approving session's `amr`. */
    readonly amr: readonly string[] | undefined;
    /** When the approving session authenticated, in whole epoch milliseconds, never after the approval's clock. */
    readonly authTimeMs: number | undefined;
}
/**
 * Whole epoch milliseconds at or after the epoch: what a store records and
 * reads back. Core-internal: `readDeviceAuthorization` reads a recorded
 * instant (an approval's, an authentication's) by it too.
 */
export declare const isRecordableInstant: (ms: number) => boolean;
/**
 * The approval's `amr` and `authTime` as a store records them, each read
 * once. `nowMs` is the approval's clock: an instant up to
 * `DEFAULT_CLOCK_SKEW_MS` ahead of it is recorded as `nowMs` (a clock a
 * little ahead, which kept as it came would read as fresh for longer than it
 * is); one further ahead is no clock's reading. Every bundled store's
 * `approve` records this answer, never its own input.
 *
 * @throws RangeError for an `amr` that is not a non-empty list of non-empty
 *   strings, or an `authTime` that is not a valid `Date` at or after the
 *   epoch and no further ahead of `nowMs` than the skew. It quotes nothing of
 *   the value.
 */
export declare function recordableDeviceApproval(approval: Pick<ApproveDeviceAuthorizationInput, "amr" | "authTime">, nowMs: number): RecordableDeviceApproval;
//# sourceMappingURL=approval.d.mts.map