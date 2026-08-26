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
	 * This endpoint is unauthenticated by design — an orchestrator has no
	 * credentials — and probe failures carry text straight from the driver:
	 * `connect ECONNREFUSED 10.0.3.14:6379` names an internal host and port.
	 * On an identity provider that is a free map of the backend network for
	 * anyone who can reach the pod. The failing dependency's *name* is what a
	 * probe consumer needs; the message goes to the log, where the operator
	 * reading it has already authenticated. Turn this on only when the
	 * endpoint is reachable solely from inside the deployment.
	 */
	readonly includeErrorDetail?: boolean;
}

/**
 * Readiness endpoint — answers whether this replica can currently serve.
 *
 * Distinct from `/_healthcheck`, which is liveness: a static 200 proving the
 * process is up and its event loop is turning. Liveness answering 200 during a
 * Redis partition is correct — restarting the process would not reconnect
 * Redis any faster — but it must not be what a load balancer uses to decide
 * whether to keep sending logins here. That is this route's job.
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

	router.get(opts.path ?? "/readyz", async (_req: Request, res: Response) => {
		const report = await runReadinessProbes(opts.probes, { timeoutMs: opts.timeoutMs });

		// An orchestrator polls this; a cached "ready" would outlive the outage
		// it describes.
		res.setHeader("Cache-Control", "no-store");

		if (!report.ready) {
			// The log keeps the full detail the body drops — the operator reading
			// it is already inside the deployment.
			opts.logger?.warn({ checks: report.checks.filter((c) => !c.ok) }, "readiness_probe_failed");
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
