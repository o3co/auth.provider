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
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	AppConfigSchema,
	createApp,
	createHealthcheckRouter,
	createReadinessRouter,
} from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import helmet from "helmet";
import { buildModules } from "./buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "./configPath.mjs";
import { createAppLogger } from "./logger.mjs";
import { createMetrics } from "./metrics.mjs";
import { installGracefulShutdown } from "./shutdown.mjs";
import { createTerminalErrorHandler } from "./terminalError.mjs";

// Step 1: Load and validate application config (HOCON → Zod schema).
// ENV = CONFIG_ENV || NODE_ENV || "development"; missing {ENV}.conf is fatal.
//
// 3-tier HOCON precedence (highest → lowest):
//   1. {env}.conf         — environment-specific overrides (e.g. production.conf)
//   2. application.conf   — template-level consumer delta
//   3. reference.conf     — library defaults shipped in @o3co/auth-provider-core
const env = process.env.CONFIG_ENV || process.env.NODE_ENV || "development";
const configDir = new URL("../config/", import.meta.url);
const configDirPath = fileURLToPath(configDir);
const { applicationConfPath, envConfPath } = resolveConfigPaths(configDirPath, env);
const libraryReferencePath = resolveLibraryReferenceConfPath();
const config: AppConfig = validate(
	parseFile(envConfPath)
		.withFallback(parseFile(applicationConfPath))
		.withFallback(parseFile(libraryReferencePath)),
	AppConfigSchema,
);

// The logger is built from config so its level is operator-controlled, and it
// is wired into `bootstrapComponents` so every module that declares
// `optional: ["logger"]` receives this one rather than falling back to its own
// default. Without that slot filled, configuring a level here would change
// nothing about what the modules emit.
const logger = createAppLogger(config);

await (async (): Promise<void> => {
	// Step 2: Create the Express app and apply base security middleware.
	const app = express();
	// `false` | `true` | a hop count | a list of IPs / CIDR ranges / named
	// ranges — the schema hands Express exactly the shapes `trust proxy`
	// already understands, validated at boot so a typo'd range fails here
	// rather than becoming a rule that silently never matches (#292). Prefer
	// naming the proxy: `true` believes a forwarded client address from anyone
	// who can reach this process, and `req.ip` is what every IP-keyed rate
	// limit is bucketed on.
	app.set("trust proxy", config.http.trustProxy);
	app.use(
		helmet({
			contentSecurityPolicy: {
				directives: {
					defaultSrc: ["'none'"],
					frameAncestors: ["'none'"],
				},
			},
		}),
	);

	// Timing middleware goes ahead of everything so the histogram covers the
	// whole stack — including responses produced by middleware that short-circuits
	// before any route runs, such as the rate limiter's 429s.
	const metrics = createMetrics();
	app.use(metrics.middleware);

	// Step 3: Boot the auth pipeline.
	// D-5: express-session middleware is now wired by `sessionStoreModule`
	// inside the boot planner. Mount order is enforced by declarationIndex
	// tie-breaking — sessionStoreModule MUST come first in `buildModules(...)`
	// so the middleware initialises `req.session` for every downstream route.
	// The connect-redis client's lifetime is owned by the planner via
	// `BuilderContext.lifecycle` and drained on `handle.dispose()`.
	// bootstrapComponents carries only host-
	// environment values (config + pathResolver per A2-γ §4 worked example);
	// every other component flows through composition-root-local modules.
	// `buildModules` is the single source of truth for the module list — it
	// gates federation modules on `config.federations.<name>.enabled`, which
	// the standalone scaffold defaults to false.
	//
	// `environment` is the name the config above was selected by (#473): the
	// Redis federation-token store's plaintext guard reads it in addition to
	// NODE_ENV, so `CONFIG_ENV=production` is production to the guard too.
	const handle = await createApp({
		modules: buildModules(config, { environment: env }),
		bootstrapComponents: {
			config,
			pathResolver: import.meta.resolve,
			logger,
		},
	});

	// Step 4: Wire host-level routes before the auth router so they remain
	// reachable even when the auth pipeline is degraded — which is exactly when
	// an operator needs an answer from them.
	//
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
			probes: handle.readinessProbes,
			timeoutMs: config.http.readinessTimeoutMs,
			logger,
		}),
	);

	// Prometheus scrape endpoint. Same reasoning as the probes above: it has to
	// keep answering while the auth pipeline is degraded, because that is when
	// the series matter.
	app.use(
		metrics.route(express, {
			probes: handle.readinessProbes,
			probeTimeoutMs: config.http.readinessTimeoutMs,
		}),
	);

	// Step 5: Mount the composed auth router and start the HTTP server.
	app.use(handle.router);
	// Terminal error handler LAST (#293 item 8): Express routes an error only
	// to handlers registered after the route that threw it. See
	// `terminalError.mts` for what it catches and why.
	app.use(createTerminalErrorHandler(logger));
	const server = app.listen(config.http.port, (): void => {
		logger.info(`Server is running on http://localhost:${config.http.port}`);
	});

	// Step 6: Graceful shutdown — handle.dispose() runs reverse-topological
	// per-component cleanup (per A2-β §8.1) plus D-5 LifecycleRegistrar drain
	// (Redis clients, interval timers).
	//
	// #290: in the template rather than a dependency, because "does SIGTERM
	// wait for in-flight requests, and for how long?" has to be answerable
	// from the code you deploy. See `shutdown.mts` for the stated guarantees
	// and for the deadline the previous implementation did not have. Size
	// `drainTimeoutMs` below your orchestrator's kill grace period.
	installGracefulShutdown(server, {
		logger,
		cleanup: () => handle.dispose(),
	});
})();
