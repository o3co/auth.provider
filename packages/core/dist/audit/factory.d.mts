import type { AuditEvent, AuditSinkBase, AuditSinkFactory } from "./types.mjs";
export declare function createAuditSinkFactory(): AuditSinkFactory;
export declare function registerBuiltinAuditSinks(factory: AuditSinkFactory): void;
/**
 * Fire-and-forget audit emitter. Dispatches `sink.record(event)` without
 * awaiting so a slow or failing sink cannot add latency to (or block) the
 * auth flow. Errors are attached to the detached promise and swallowed.
 * No-op when sink is undefined.
 *
 * Returns synchronously as far as the caller is concerned — the sink's
 * promise is observed only by the `.catch` handler below. Callers MAY
 * `await` this function for symmetry; doing so does not wait for the sink.
 */
export declare function emitAuditEvent(sink: AuditSinkBase | undefined, event: AuditEvent): Promise<void>;
//# sourceMappingURL=factory.d.mts.map