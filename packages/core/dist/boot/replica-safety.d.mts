import type { Logger } from "../logging/Logger.mjs";
/**
 * Names of the modules {@link checkReplicaSafety} refuses in multi-replica
 * mode. Exported so a composition root can run the same check itself, and so
 * the set is greppable from a deployment's own tests.
 */
export declare const REPLICA_UNSAFE_MODULES: readonly string[];
export interface CheckReplicaSafetyInput {
    readonly modules: readonly {
        readonly name: string;
    }[];
    /** Parsed application config; only `deployment.mode` is read. */
    readonly config: unknown;
    readonly logger?: Logger;
}
/**
 * Composition-root guard for replica-unsafe state (#271).
 *
 * Three states, because "is this deployment scaled?" has three honest answers
 * and collapsing them to two makes one of them useless:
 *
 *   - **`deployment.mode = "multi"`** — the operator has said there is more
 *     than one replica, so any in-memory shared state is a defect and boot
 *     fails naming every offender.
 *   - **`deployment.mode = "single"`** — the operator has said there is one.
 *     In-memory state is correct and this says nothing. Warning anyway would
 *     fire on every local run and train people to ignore the warning that
 *     matters.
 *   - **unset** — nothing has been said. This is where the 3am scenario starts,
 *     so it is the state that has to be loud: one consolidated warning naming
 *     what is in memory and what each one costs when scaled.
 *
 * Which is why `deployment.mode` has **no literal default in HOCON**. A baked-in
 * `"single"` would make the unset state unreachable and the warning dead code.
 *
 * **This cannot catch the operator who scales without ever setting
 * `deployment.mode`** — the case the issue describes. A process whose state is
 * entirely in its own memory has no shared medium through which to observe
 * peers, so the condition is undetectable from inside precisely when it is
 * true. The warning and the documentation are what address that; the failure
 * mode is for operators who have declared their shape.
 */
export declare function checkReplicaSafety({ modules, config, logger }: CheckReplicaSafetyInput): void;
//# sourceMappingURL=replica-safety.d.mts.map