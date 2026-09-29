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

import type { Request, Response, Router } from "express";
import type { EventLogger } from "../logging/Logger.mjs";
import { runReadinessProbes } from "../readiness/run.mjs";
import type { ReadinessProbe } from "../readiness/types.mjs";

export interface ReadinessRouterOptions {
	/** The probes to run, in registration order. */
	readonly probes: readonly ReadinessProbe[];
	/**
	 * Per-probe deadline in milliseconds. Required rather than defaulted: the
	 * right value depends on the orchestrator's own probe timeout, which only
	 * the composition root knows, and a default here would be a second place
	 * for that number to live.
	 */
	readonly timeoutMs: number;
	/**
	 * When wired, an unready result is logged at warn with the failing checks
	 * — including each failure's message, which the response body omits.
	 *
	 * Typed as {@link EventLogger} rather than `Logger`: readiness is what an
	 * operator reaches for while things are already broken, and it should not
	 * be the endpoint that is hardest to wire.
	 */
	readonly logger?: EventLogger;
	/** Route path. Defaults to `/readyz`. */
	readonly path?: string;
	/**
	 * Include each failing probe's error message in the response body.
	 * Defaults to `false`.
	 *
	 * The endpoint is unauthenticated (an orchestrator has no credentials), and
	 * a driver message such as `connect ECONNREFUSED 10.0.3.14:6379` maps the
	 * backend network for anyone who can reach the pod. The body names the
	 * failing dependency; the message goes to the log. Turn this on only when
	 * the endpoint is reachable solely from inside the deployment.
	 */
	readonly includeErrorDetail?: boolean;
}

/**
 * Readiness endpoint: answers whether this replica can currently serve.
 *
 * Distinct from `/_healthcheck` (liveness), which rightly stays 200 during a
 * Redis partition since a restart would not reconnect faster. A load balancer
 * deciding whether to keep sending logins here uses this route.
 *
 * Mount it on the host app ahead of the composed auth router so it stays
 * reachable while the auth pipeline is degraded.
 */
export function createRouter(
	express: { Router: () => Router },
	opts: ReadinessRouterOptions,
): Router {
	const router = express.Router();
	const includeErrorDetail = opts.includeErrorDetail === true;
	// Held for the router's lifetime so concurrent and repeated scrapes join one
	// in-flight check per dependency instead of queueing a command each. During
	// a partition the driver never answers, and this endpoint is reachable
	// without credentials.
	const inFlight = new Map<string, Promise<unknown>>();

	router.get(opts.path ?? "/readyz", async (_req: Request, res: Response) => {
		const report = await runReadinessProbes(opts.probes, {
			timeoutMs: opts.timeoutMs,
			inFlight,
		});

		// An orchestrator polls this; a cached "ready" would outlive the outage
		// it describes.
		res.setHeader("Cache-Control", "no-store");

		if (!report.ready) {
			// The log keeps the detail the body drops, as each failed check's
			// projection. At warn: a 503 here signals the orchestrator; it does not
			// refuse a client.
			opts.logger?.warn(
				{
					checks: report.checks
						.filter((c) => !c.ok)
						.map(({ name, durationMs, err }) => ({ name, durationMs, err })),
				},
				"readiness_probe_failed",
			);
		}

		res.status(report.ready ? 200 : 503).json({
			status: report.ready ? "ready" : "unready",
			checks: report.checks.map(({ name, ok, durationMs, error }) => ({
				name,
				ok,
				durationMs,
				...(includeErrorDetail && error !== undefined ? { error } : {}),
			})),
		});
	});

	return router;
}
