import type { ReadinessProbe, ReadinessReport } from "./types.mjs";
export interface RunReadinessOptions {
    /**
     * Per-probe deadline. A probe that has not settled by then is reported as
     * failed. This has to be shorter than whatever scrape interval the
     * orchestrator uses, or an unready pod reads as a slow one.
     */
    readonly timeoutMs: number;
    /**
     * Caller-owned map of checks that have not settled yet, keyed by probe name.
     *
     * Abandoning a check at the deadline does not cancel it. Against a
     * partitioned Redis the driver holds the `PING` in its offline queue until
     * reconnect, so without this every scrape adds another pending command —
     * unbounded during a long outage, and released as a burst on recovery. With
     * it, a probe whose previous check is still running is *joined* rather than
     * re-issued: one in-flight command per dependency no matter how often the
     * endpoint is scraped. Each caller still applies its own deadline, so a
     * joining request does not inherit how long the shared check has already
     * been waiting.
     *
     * Pass the same map across calls (the readiness router holds one for its
     * lifetime). Omit it and every call issues its own check.
     */
    readonly inFlight?: Map<string, Promise<unknown>>;
}
/**
 * Run every probe concurrently under a shared per-probe deadline.
 *
 * A dependency being down must not hide the state of the others, so no probe
 * short-circuits the rest: each one is reported individually and `ready` is
 * simply the conjunction. A deployment that registered no probes is ready —
 * absence of a wired dependency is not evidence of a broken one.
 */
export declare function runReadinessProbes(probes: readonly ReadinessProbe[], options: RunReadinessOptions): Promise<ReadinessReport>;
//# sourceMappingURL=run.d.mts.map