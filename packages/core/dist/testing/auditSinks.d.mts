/**
 * Audit doubles for tests: an `AuditSink` that keeps every event it is handed
 * and can stand in for a sink that is down, and a module that contributes
 * sinks as `auditHooks`.
 */
import type { AuditEvent, AuditSink } from "../audit/types.mjs";
import { type Module } from "../modules/manifest/index.mjs";
export interface RecordingAuditSink extends AuditSink {
    readonly kind: "recording";
    /** Every event it was handed, oldest first, each the object it was handed. */
    readonly events: readonly AuditEvent[];
    /** From now on, every record rejects with `error` and keeps nothing. */
    failWith(error: unknown): void;
    /** Record again. */
    recover(): void;
}
export declare function createRecordingAuditSink(): RecordingAuditSink;
/**
 * A module named `audit-hooks-<name>` that contributes each of `hooks` as an
 * `auditHooks` entry, in order. `name` is one kebab-case word or more.
 */
export declare function auditHooksModule(name: string, ...hooks: readonly AuditSink[]): Module;
//# sourceMappingURL=auditSinks.d.mts.map