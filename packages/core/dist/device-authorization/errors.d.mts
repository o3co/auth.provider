/**
 * Why a `DeviceCodeStore` refused an operation.
 *
 * - `"full"` — `create` found the store at its cap with every resident
 *   record live (#445). A bounded adapter throws this instead of evicting: a
 *   pending or approved-not-yet-polled record is a human's answer in flight,
 *   which nothing can reconstruct, whereas the request being refused can
 *   simply be made again. The device authorization endpoint answers it
 *   without re-drawing a code, because the store refused the slot, not the
 *   code.
 *
 * A code collision is deliberately *not* a reason here. The port lets any
 * adapter refuse a collision however it likes — the conformance suite asks
 * only that `create` rejects — and the endpoint treats every error that is
 * not `"full"` as one to re-draw for.
 */
export type DeviceCodeStoreErrorReason = "full";
/**
 * Single discriminated-reason error class for `DeviceCodeStore` adapters.
 * Mirrors `ChallengeStorageError` / `RefreshTokenStorageError` discipline
 * (one class, discriminated reason, no per-reason subclasses), so a caller
 * that must tell one refusal from another switches on a field rather than
 * on a message.
 */
export declare class DeviceCodeStoreError extends Error {
    readonly reason: DeviceCodeStoreErrorReason;
    constructor(opts: {
        reason: DeviceCodeStoreErrorReason;
        message?: string;
        cause?: unknown;
    });
}
//# sourceMappingURL=errors.d.mts.map