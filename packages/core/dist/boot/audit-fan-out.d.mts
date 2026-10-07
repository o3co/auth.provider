import type { AuditSink } from "../audit/types.mjs";
import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import type { BootPlan, ContributionCollectorMap, NormalisedModule } from "./types.mjs";
/** Whether any module contributes an `auditHooks` entry: then core fills `auditSink`. */
export declare function contributesAuditHooks(modules: readonly NormalisedModule[]): boolean;
/** What stage 3 does to the `auditSink` slot. */
export interface AuditSlot {
    /** Before any provider runs: wraps a host's sink, or fills the slot when no provider will. */
    beforeProviders(): void;
    /** The value the working map holds for a provider's `value` under `key`. */
    provided(key: ComponentKey, value: unknown): unknown;
}
/**
 * Stage 3's handling of the `auditSink` slot in `components`, the working
 * map. Without an `auditHooks` contribution it leaves the slot as whatever
 * fills it. With one, the slot holds the fan-out over the host's sink, a
 * provider's, or none; the hooks are read from the `auditHooks` collector at
 * each event, and a failing sink is reported to the `logger` component the
 * map holds at that moment. A provider's cleanup is still handed its own
 * value.
 *
 * Disposing the fan-out disposes the slot's own sink when that sink has a
 * `Symbol.asyncDispose`, so boot's dispose reaches it as it would unwrapped.
 * The hooks are contributions and are not disposed.
 *
 * The fan-out is core's own and frozen, its disposable copy included, so a
 * write to the slot's value throws in strict-mode code. The sink it wraps is
 * the host's or the provider's and is not frozen, and without an
 * `auditHooks` contribution the slot holds that sink as it was given.
 *
 * A contributed hook with no `auditHooks` collector to read is a broken
 * invariant (the planner always merges it), refused rather than left a
 * fan-out to nothing.
 */
export declare function auditSlotFor(plan: BootPlan, contributionKinds: ContributionCollectorMap | undefined, components: Record<string, unknown>): AuditSlot;
/**
 * Stage 4's record of the `auditHooks` contributions: each value checked as
 * it registers, and the module that contributed it kept for the boot line.
 */
export interface AuditHookRegistrations {
    /** `value`, a hook `module` contributed, or a `RangeError` when it is no sink. */
    registered(value: unknown, module: string): AuditSink;
    /**
     * Logs `audit_hooks_registered` at info when any hook registered: each
     * hook's position, as `audit_sink_failed` names it (`sink`, from 1), and
     * the module that contributed it.
     */
    log(components: Record<string, unknown>, collector: ContributionCollectorMap["auditHooks"]): void;
}
export declare function auditHookRegistrations(): AuditHookRegistrations;
//# sourceMappingURL=audit-fan-out.d.mts.map