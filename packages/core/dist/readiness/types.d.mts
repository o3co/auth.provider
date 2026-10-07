/**
 * A liveness signal for one backing dependency.
 *
 * Probes are registered by whoever *owns* the connection — the builder that
 * opened it — because that is the only place holding a reference to it. An
 * adapter's public interface is a narrow command surface (get / set / del),
 * deliberately without a `ping`, so the composition root cannot construct
 * this from the outside.
 */
export interface ReadinessProbe {
    /**
     * Identifies the dependency in the readiness response. Use the resource,
     * not the module: `"redis"`, `"session-store"`, `"database"`.
     */
    readonly name: string;
    /**
     * Resolve when the dependency is reachable; throw or reject when it is
     * not. The return value is ignored — only settlement matters.
     */
    check(): Promise<unknown>;
}
/**
 * Passed to adapter builders via `BuilderContext.readiness`. Builders
 * that open a connection SHOULD register a probe for it:
 *
 *     ctx.readiness?.register({ name: "redis", check: () => client.ping() })
 *
 * Mirrors `LifecycleRegistrar`: the boot planner owns the instance and
 * seeds it as the `readinessRegistrar` bootstrap component, so a builder
 * reached through a module that declares `optional: ["readinessRegistrar"]`
 * receives it. Always use optional chaining — a factory constructed outside
 * the boot planner (unit tests) receives `{}` as its context.
 */
export interface ReadinessRegistrar {
    register(probe: ReadinessProbe): void;
}
/**
 * Registrar plus the planner-side read of what was registered.
 *
 * @internal — used by the boot planner; not part of the consumer-facing API.
 */
export interface InternalReadinessRegistrar extends ReadinessRegistrar {
    /** Probes in registration order. @internal */
    _probes(): readonly ReadinessProbe[];
}
/** Outcome of a single probe. */
export interface ProbeResult {
    readonly name: string;
    readonly ok: boolean;
    /** Wall-clock duration of the probe in milliseconds. */
    readonly durationMs: number;
    /** Failure reason, present only when `ok` is false. */
    readonly error?: string;
}
/** Aggregate outcome across every registered probe. */
export interface ReadinessReport {
    /** True only when every probe succeeded. A deployment with no probes is ready. */
    readonly ready: boolean;
    readonly checks: readonly ProbeResult[];
}
//# sourceMappingURL=types.d.mts.map