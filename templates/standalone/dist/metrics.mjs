/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { runReadinessProbes } from "@o3co/auth-provider-core";
import { collectDefaultMetrics, Gauge, Histogram, Registry } from "prom-client";
/**
 * Route label for a request.
 *
 * Express only fills `req.route` once a handler has matched, and the label has
 * to be **bounded**: labelling by `req.path` would mint a new time series per
 * distinct URL, and this server's paths carry opaque values (`/oauth/authorize`
 * query state, 404 probes from the internet). An unbounded label set is the
 * classic way to take Prometheus down with the thing that was supposed to
 * watch it. Unmatched requests collapse to a single `unmatched` bucket.
 */
/**
 * Method label, bounded to the methods this server can actually serve.
 *
 * `req.method` is attacker-controlled: Node's HTTP parser accepts any valid
 * token, so `FOO` and `M000001` reach here as readily as `GET`. Each distinct
 * value would mint a fresh histogram child carrying every bucket — the same
 * unbounded-cardinality failure {@link routeLabel} guards against, one label
 * over, and reachable without any access to `/metrics` itself.
 */
const KNOWN_METHODS = new Set([
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "TRACE",
    "CONNECT",
]);
function methodLabel(req) {
    return KNOWN_METHODS.has(req.method) ? req.method : "other";
}
function routeLabel(req) {
    const route = req.route?.path;
    if (typeof route === "string" && route.length > 0) {
        return req.baseUrl ? `${req.baseUrl}${route === "/" ? "" : route}` : route;
    }
    return "unmatched";
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
export function createMetrics() {
    const registry = new Registry();
    collectDefaultMetrics({ register: registry, prefix: "auth_provider_" });
    const requestDuration = new Histogram({
        name: "http_request_duration_seconds",
        help: "HTTP request latency in seconds, by method, route and status.",
        labelNames: ["method", "route", "status"],
        // Tuned for an IdP: token and authorize calls sit in the low tens of
        // milliseconds when healthy, and the tail is what an outage moves.
        buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
        registers: [registry],
    });
    const middleware = (req, res, next) => {
        const endTimer = requestDuration.startTimer();
        let observed = false;
        // Both terminal events, with a guard, rather than `finish` alone.
        // `finish` covers every response the server completes — including ones
        // produced by an error handler, and `req.route` is populated by then. But
        // a client or proxy that disconnects mid-handler emits `close` WITHOUT
        // `finish`, and those are disproportionately the slow and failing requests
        // that RED metrics exist to surface; counting only `finish` would drop
        // them from both the rate and the latency series.
        const observe = () => {
            if (observed)
                return;
            observed = true;
            endTimer({
                method: methodLabel(req),
                route: routeLabel(req),
                status: String(res.statusCode),
            });
        };
        res.once("finish", observe);
        res.once("close", observe);
        next();
    };
    const dependencyUp = new Gauge({
        name: "auth_dependency_up",
        help: "1 when a backing dependency answered its readiness probe, 0 otherwise.",
        labelNames: ["dependency"],
        registers: [registry],
    });
    // Shared across scrapes so a partitioned backend does not accumulate one
    // in-flight command per scrape (see `runReadinessProbes`).
    const inFlight = new Map();
    const route = (express, opts) => {
        const router = express.Router();
        router.get(opts.path ?? "/metrics", async (_req, res) => {
            // Sampled per scrape rather than held as state: a cached value would
            // report a dependency healthy for as long as the cache lives, which is
            // exactly the window an incident lives in.
            const report = await runReadinessProbes(opts.probes, {
                timeoutMs: opts.probeTimeoutMs,
                inFlight,
            });
            for (const check of report.checks) {
                dependencyUp.set({ dependency: check.name }, check.ok ? 1 : 0);
            }
            res.setHeader("Content-Type", registry.contentType);
            res.setHeader("Cache-Control", "no-store");
            res.send(await registry.metrics());
        });
        return router;
    };
    return { middleware, route };
}
