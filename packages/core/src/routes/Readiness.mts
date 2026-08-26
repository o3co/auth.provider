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
import { runReadinessProbes } from "../readiness/run.mjs";
import type { ReadinessProbe } from "../readiness/types.mjs";

/** The one logging call this route makes. See {@link ReadinessRouterOptions.logger}. */
export interface ReadinessLogger {
	warn(obj: Record<string, unknown>, msg: string): void;
}

export interface ReadinessRouterOptions {
	/**
	 * The probes to run. Read on every request rather than captured, so a
	 * registrar still collecting probes during boot can be passed directly.
	 */
	readonly probes: readonly ReadinessProbe[];
	/** Per-probe deadline in milliseconds. Defaults to 1000. */
	readonly timeoutMs?: number;
	/**
	 * When wired, an unready result is logged at warn with the failing checks.
	 *
	 * Typed as the single call this route makes rather than as the full
	 * {@link Logger}. Readiness is what an operator reaches for while things
	 * are already broken; requiring a logger to also carry `trace` / `fatal` /
	 * `child` to be accepted here would make the endpoint the hardest thing in
	 * the app to wire, and both `Logger` and the leaner logger the standalone
	 * template ships satisfy this shape.
	 */
	readonly logger?: ReadinessLogger;
	/** Route path. Defaults to `/readyz`. */
	readonly path?: string;
}

const DEFAULT_TIMEOUT_MS = 1000;

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
	const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

	router.get(opts.path ?? "/readyz", async (_req: Request, res: Response) => {
		const report = await runReadinessProbes(opts.probes, { timeoutMs });

		// An orchestrator polls this; a cached "ready" would outlive the outage
		// it describes.
		res.setHeader("Cache-Control", "no-store");

		if (!report.ready) {
			opts.logger?.warn({ checks: report.checks.filter((c) => !c.ok) }, "readiness_probe_failed");
		}

		res.status(report.ready ? 200 : 503).json({
			status: report.ready ? "ready" : "unready",
			checks: report.checks,
		});
	});

	return router;
}
