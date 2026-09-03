import type { ReadinessProbe } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
export interface MetricsRouteOptions {
    /**
     * Readiness probes, sampled on each scrape to publish a per-dependency
     * up/down gauge. Pass `handle.readinessProbes`.
     */
    readonly probes: readonly ReadinessProbe[];
    /** Per-probe deadline, in milliseconds. Use `config.http.readinessTimeoutMs`. */
    readonly probeTimeoutMs: number;
    /** Route path. Defaults to `/metrics`. */
    readonly path?: string;
}
export interface Metrics {
    /**
     * Mount FIRST, ahead of every route: it times the whole downstream stack,
     * and it records on the response's `finish` event so a request that ends in
     * an error handler is still counted.
     */
    readonly middleware: RequestHandler;
    /**
     * Mounts the scrape endpoint.
     *
     * The probes arrive here rather than at construction because the two halves
     * are needed at different moments: the middleware has to be mounted before
     * the app boots, and the probes only exist afterwards, on the `AppHandle`.
     */
    readonly route: (express: {
        Router: () => Router;
    }, options: MetricsRouteOptions) => Router;
}
/**
 * Prometheus metrics for the standalone provider.
 *
 * What this publishes is chosen from what an operator cannot otherwise see.
 * Before it, a degraded provider offered stderr lines and the load balancer's
 * 5xx graph — no way to distinguish "rate limiter is failing closed" from
 * "Redis-backed code repository is gone" without grepping container logs, and
 * no latency series to alert on at all.
 *
 * - `http_request_duration_seconds` — histogram by method, bounded route, and
 *   status. Carries request rate, error rate and latency in one series, which
 *   is the whole RED method.
 * - `auth_dependency_up` — 1/0 per readiness probe, sampled at scrape time.
 *   This is the series that separates "Redis is gone" from "the app is slow",
 *   and it reuses the probes the builders already registered rather than
 *   inventing a second notion of what this deployment depends on.
 * - Node process defaults (event-loop lag, heap, GC, handles) under the
 *   `auth_provider_` prefix.
 *
 * Deliberately not here yet: rate-limiter fail-closed counts and audit-sink
 * drops. Both happen inside `@o3co/auth-provider-core` and neither is
 * observable from the composition root today; counting them needs a metrics
 * hook in core (`BuilderContext` already reserves `metrics`) rather than
 * something this file can reach.
 */
export declare function createMetrics(): Metrics;
//# sourceMappingURL=metrics.d.mts.map