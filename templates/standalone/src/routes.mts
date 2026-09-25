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

/*
 * The host's routes, in the order `app.mts` mounts them: liveness, readiness
 * and the metrics scrape ahead of the composed auth router — so they keep
 * answering while the auth pipeline is degraded, which is when an operator
 * needs them — then that router, then the terminal error handler, last,
 * because Express hands an error only to handlers mounted after the route
 * that raised it. A function rather than inline in `app.mts`, so the order
 * and the handler can be tested as the process mounts them.
 */

import {
	createHealthcheckRouter,
	createReadinessRouter,
	type Logger,
	type ReadinessProbe,
} from "@o3co/auth-provider-core";
import express, { type Express, type Router } from "express";
import type { Metrics } from "./metrics.mjs";
import { createTerminalErrorHandler } from "./terminalError.mjs";

export interface MountRoutesOptions {
	/** The router `createApp` composed (`handle.router`). */
	readonly router: Router;
	/** The readiness probes the builders registered (`handle.readinessProbes`). */
	readonly probes: readonly ReadinessProbe[];
	/** Per-probe deadline, in milliseconds: `config.http.readinessTimeoutMs`. */
	readonly readinessTimeoutMs: number;
	readonly metrics: Metrics;
	readonly logger: Logger;
}

/** Mount the host's routes, the composed router and the terminal error handler on `app`. */
export function mountRoutes(app: Express, options: MountRoutesOptions): void {
	// Liveness: the process is up and its event loop is turning. Deliberately
	// static — restarting the process would not bring Redis back, so a Redis
	// outage must not read as "this container is broken, kill it".
	app.use(createHealthcheckRouter(express));

	// Readiness: can this replica serve right now? Redis backs sessions,
	// authorization codes and refresh-token families in the deployable
	// defaults, so a replica that has lost it answers 503 here and should be
	// taken out of rotation. Probes are contributed by the builders that own
	// each connection; a memory-only deployment registers none and is always
	// ready.
	app.use(
		createReadinessRouter(express, {
			probes: options.probes,
			timeoutMs: options.readinessTimeoutMs,
			logger: options.logger,
		}),
	);

	// Prometheus scrape endpoint. Same reasoning as the probes above: it has to
	// keep answering while the auth pipeline is degraded, because that is when
	// the series matter.
	app.use(
		options.metrics.route(express, {
			probes: options.probes,
			probeTimeoutMs: options.readinessTimeoutMs,
		}),
	);

	// The composed auth router.
	app.use(options.router);
	// Terminal error handler LAST (#293 item 8): Express routes an error only
	// to handlers registered after the route that threw it. The composed
	// router answers its own errors (core's terminal handler ends it), so
	// this one catches the host routes' above. See `terminalError.mts`.
	app.use(createTerminalErrorHandler(options.logger));
}
