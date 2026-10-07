/**
 * The sweep interval when `core.sessionLifecycle.sweepIntervalSeconds` is not
 * written, in whole seconds: a close left pending, its user session already
 * gone, waits at most this long for no later close to resume it.
 */
export declare const DEFAULT_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS = 60;
/** The longest sweep interval, in whole seconds: the longest delay a timer takes. */
export declare const MAX_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS: number;
/**
 * `core.sessionLifecycle.sweepIntervalSeconds` in milliseconds, read as
 * core's numbers are (`configuredNumber`):
 * {@link DEFAULT_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS} when it is not
 * written, and `undefined` for 0, which turns the sweep off. Anything but a
 * whole number of seconds from 0 to
 * {@link MAX_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS} is a RangeError naming
 * the key.
 */
export declare function readSessionLifecycleSweepIntervalMs(config: unknown): number | undefined;
export declare const SESSION_LIFECYCLE_MODULE = "core-session-lifecycle";
/**
 * Why boot refuses a composition that serves relying parties (the
 * `clientRepository` slot is filled) and contributes no notifier: judged at
 * the end of the contributions, once the notifier would have registered.
 */
export declare const SESSION_LIFECYCLE_NOTIFIER_MISSING: string;
export declare const sessionLifecycleModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=module.d.mts.map