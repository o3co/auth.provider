/**
 * boot/run-cleanups.mts: the rollback of a refused boot. Runs the lifecycle
 * cleanups stage 3 recorded, in reverse, before the refusal propagates; the
 * stage that refuses calls it, once.
 */
import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import type { CleanupRecord } from "./types.mjs";
/** A cleanup that threw during a rollback, as `details.cleanupErrors` holds it. */
export interface CleanupError {
    readonly module: string;
    readonly componentKey: ComponentKey;
    readonly error: unknown;
}
/**
 * Runs `cleanupRecords` in reverse order, best-effort: a cleanup that throws
 * does not stop the rest, and its error is returned, in the order run.
 * @internal
 */
export declare function runCleanupsReverse(cleanupRecords: readonly CleanupRecord[]): Promise<readonly CleanupError[]>;
//# sourceMappingURL=run-cleanups.d.mts.map