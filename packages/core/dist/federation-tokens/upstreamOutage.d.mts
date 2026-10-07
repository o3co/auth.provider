/**
 * An Error — this realm's or another's (`Error.isError` where the runtime has
 * it) — and not a plain object shaped like one: what a library raised, never
 * what a peer's parsed body says. Asking never throws. The refresh-error
 * classifier follows a cause by the same test (`refresh-error.mts`).
 */
export declare const isError: (value: unknown) => value is object;
/** Whether `error`, a failed upstream call, is the upstream's outage rather than its answer. */
export declare function isFederationUpstreamOutage(error: unknown): boolean;
//# sourceMappingURL=upstreamOutage.d.mts.map