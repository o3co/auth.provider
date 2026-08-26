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

export interface HealthcheckRouterOptions {
	/** Route path. Defaults to `/_healthcheck`. */
	readonly path?: string;
}

/**
 * Liveness endpoint — answers whether this process is up and its event loop is
 * turning. Always `200`, and deliberately so: it touches no dependency.
 *
 * The counterpart is `routes/Readiness.mts`. Wiring liveness to anything that
 * probes a backing service turns one dependency outage into a cluster-wide
 * restart loop, which reconnects nothing and adds cold starts to an incident.
 * Losing Redis is a reason to stop routing to a replica, not to kill it.
 *
 * Mount it on the host app ahead of the composed auth router so it stays
 * reachable while the auth pipeline is degraded.
 */
export function createRouter(
	express: { Router: () => Router },
	opts: HealthcheckRouterOptions = {},
): Router {
	const router = express.Router();

	router.get(opts.path ?? "/_healthcheck", (_req: Request, res: Response) => {
		res.status(200).json({ status: "ok" });
	});

	return router;
}
