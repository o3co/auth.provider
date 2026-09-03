/**
 * Builder context passed to every adapter builder.
 *
 * Intentionally minimal in v1 — all fields are optional and future additions are
 * guaranteed to be additive-only (non-breaking). Builders may ignore fields they
 * do not need. Planned future fields:
 *   - logger?: Logger         (startup-time logging, added when logger injection lands)
 *   - abortSignal?: AbortSignal (timeout-aware init, e.g. database connections)
 *   - tracer?: Tracer         (OpenTelemetry context propagation)
 *   - metrics?: MetricsRecorder (metrics backend injection)
 */
export interface BuilderContext {
}
/**
 * Factory builder function: given raw config plus a {@link BuilderContext}, produce
 * an adapter instance (sync or async).
 *
 * The `ctx` parameter is always a frozen snapshot captured at factory creation time;
 * builders must not assume they can mutate it.
 */
export type AdapterBuilder<T> = (config: Record<string, unknown>, ctx: Readonly<BuilderContext>) => T | Promise<T>;
/**
 * Name-based adapter registry. Consumers create one factory per "kind" (domain),
 * register a builder per concrete adapter type, and resolve an instance at startup
 * via {@link AdapterFactory.create}.
 */
export interface AdapterFactory<T> {
    /**
     * Register a builder for `type`. Throws if `type` is already registered
     * (silent-override prevention). Consumers needing override semantics must
     * create a new factory instance.
     */
    register(type: string, builder: AdapterBuilder<T>): void;
    /**
     * Resolve an adapter from config. The `type` field selects the builder;
     * the full config object (including `type`) is forwarded to the builder
     * alongside the factory-level {@link BuilderContext}.
     *
     * Always returns `Promise<T>` regardless of whether the builder is sync or async.
     */
    create(config: {
        type: string;
    } & Record<string, unknown>): Promise<T>;
    /**
     * Snapshot of currently registered type names. Used by error messages and tests.
     */
    registeredTypes(): string[];
}
/**
 * Construct a fresh {@link AdapterFactory} for a single domain.
 *
 * @param kind human-readable label used in error messages (e.g. "UserRepository")
 * @param ctx  factory-level BuilderContext passed to every builder. Defaults to `{}`.
 */
export declare function createAdapterFactory<T>(kind: string, ctx?: BuilderContext): AdapterFactory<T>;
export declare class AdapterFactoryError extends Error {
    readonly reason: "unknown" | "duplicate";
    readonly kind: string;
    readonly type: string;
    readonly registered: readonly string[];
    constructor(args: {
        reason: "unknown" | "duplicate";
        kind: string;
        type: string;
        registered: readonly string[];
    });
}
//# sourceMappingURL=AdapterFactory.d.mts.map