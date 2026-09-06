/**
 * Minimal structural logger interface used by @o3co/auth-provider internals.
 *
 * Structurally compatible with `console`, pino, winston, bunyan, etc. Consumers
 * can pass any object matching the subset of methods used at each call site.
 *
 * Additional methods (`info`, `error`, `debug`) will be added when an internal
 * call site needs them — kept minimal until then to avoid implementers having
 * to stub unused methods.
 */
export interface Logger {
    warn(message: string, ...args: unknown[]): void;
}
//# sourceMappingURL=Logger.d.mts.map