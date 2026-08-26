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

import type { ReadinessProbe } from "@o3co/auth-provider-core";
import { runReadinessProbes } from "@o3co/auth-provider-core";
import type { NextFunction, Request, RequestHandler, Response, Router } from "express";
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
function routeLabel(req: Request): string {
	const route = (req as Request & { route?: { path?: string } }).route?.path;
	if (typeof route === "string" && route.length > 0) {
		return req.baseUrl ? `${req.baseUrl}${route === "/" ? "" : route}` : route;
	}
	return "unmatched";
}

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
	readonly route: (express: { Router: () => Router }, options: MetricsRouteOptions) => Router;
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
export function createMetrics(): Metrics {
	const registry = new Registry();
	collectDefaultMetrics({ register: registry, prefix: "auth_provider_" });

	const requestDuration = new Histogram({
		name: "http_request_duration_seconds",
		help: "HTTP request latency in seconds, by method, route and status.",
		labelNames: ["method", "route", "status"] as const,
		// Tuned for an IdP: token and authorize calls sit in the low tens of
		// milliseconds when healthy, and the tail is what an outage moves.
		buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
		registers: [registry],
	});

	const middleware: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
		const endTimer = requestDuration.startTimer();
		// `finish` rather than wrapping `res.end`: it fires for every terminal
		// path including the error handler, and `req.route` is populated by then.
		res.once("finish", () => {
			endTimer({
				method: req.method,
				route: routeLabel(req),
				status: String(res.statusCode),
			});
		});
		next();
	};

	const dependencyUp = new Gauge({
		name: "auth_dependency_up",
		help: "1 when a backing dependency answered its readiness probe, 0 otherwise.",
		labelNames: ["dependency"] as const,
		registers: [registry],
	});

	// Shared across scrapes so a partitioned backend does not accumulate one
	// in-flight command per scrape (see `runReadinessProbes`).
	const inFlight = new Map<string, Promise<unknown>>();

	const route = (express: { Router: () => Router }, opts: MetricsRouteOptions): Router => {
		const router = express.Router();
		router.get(opts.path ?? "/metrics", async (_req: Request, res: Response) => {
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
