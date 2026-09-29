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
import { type AppConfig, createApp } from "@o3co/auth-provider-core";
import express from "express";
import helmet from "helmet";
import { buildModules, withSessionRequirements } from "./buildModules.mjs";
import { readOwnLayers, readSwitches, resolveConfigPaths, resolveForBoot } from "./configPath.mjs";
import { listen } from "./listen.mjs";
import { createAppLogger } from "./logger.mjs";
import { createMetrics } from "./metrics.mjs";
import { mountRoutes } from "./routes.mjs";
import { cleanupAllowanceFor, installGracefulShutdown } from "./shutdown.mjs";

// Step 1: the configuration, in two phases (#728).
// ENV = CONFIG_ENV || NODE_ENV || "development"; missing {ENV}.conf is fatal.
//
// HOCON precedence (highest → lowest):
//   1. {env}.conf         — environment-specific overrides (e.g. production.conf)
//   2. application.conf   — template-level consumer delta
//   3. reference.conf     — each loaded package's defaults, then core's
const env = process.env.CONFIG_ENV || process.env.NODE_ENV || "development";
const configDir = new URL("../config/", import.meta.url);
const configDirPath = fileURLToPath(configDir);
const { applicationConfPath, envConfPath } = resolveConfigPaths(configDirPath, env);
// The template's own layers, read once — each file parsed once, under one
// snapshot of the environment — so both phases below read the same thing: a
// file replaced, or a variable changed, while the process starts cannot make
// boot parse something other than what the modules were chosen by.
const own = readOwnLayers([envConfPath, applicationConfPath]);
// Phase one, transitional (#728): what the template reads before it knows
// its modules — the switches `buildModules` chooses them by, the log level,
// `mfa.mode` — from its own layers over core's reference.conf, with core's
// transitional reader. Only for those choices: the configuration the
// modules read is phase two's, parsed by `createApp`. The session-admission
// ADR's D7: what this composition expects of session admission is derived
// from the parsed `mfa.mode`, in TypeScript, and written into the
// configuration boot compares with what registers.
const switches: AppConfig = withSessionRequirements(readSwitches(own));

// The logger is built from config so its level is operator-controlled, and it
// is wired into `bootstrapComponents` so every module that declares
// `optional: ["logger"]` receives this one rather than falling back to its own
// default. Without that slot filled, configuring a level here would change
// nothing about what the modules emit.
const logger = createAppLogger(switches);

await (async (): Promise<void> => {
	// Step 2: Create the Express app and apply base security middleware.
	// `trust proxy` is set from the parsed configuration once boot has it
	// (step 3), before a request can arrive.
	const app = express();
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
	// `logger` is where the composition's own notices go (a deprecated config
	// key), the same logger every module gets through the slot below.
	//
	// Phase two (#728): `createApp` is handed the configuration as resolved —
	// the template's own layers, the same read, over the reference.conf of every package its
	// modules come from, core's last — and parses it once, with every loaded
	// module's schema; a section is never stripped on the way. What the
	// template reads from here on it reads from the parsed configuration.
	const modules = buildModules(switches, { environment: env, logger });
	const handle = await createApp({
		modules,
		bootstrapComponents: {
			config: resolveForBoot(own, modules, switches.sessionRequirements),
			pathResolver: import.meta.resolve,
			logger,
		},
	});
	const config = handle.components.config;
	if (config === undefined) throw new Error("createApp booted without the parsed configuration");
	// `false` | `true` | a hop count | a list of IPs / CIDR ranges / named
	// ranges — the schema hands Express exactly the shapes `trust proxy`
	// already understands, validated at boot so a typo'd range fails there
	// rather than becoming a rule that silently never matches (#292). Prefer
	// naming the proxy: `true` believes a forwarded client address from anyone
	// who can reach this process, and `req.ip` is what every IP-keyed rate
	// limit is bucketed on.
	app.set("trust proxy", config.http.trustProxy);

	// Step 4: the host-level routes (liveness, readiness, metrics) ahead of the
	// auth router so they remain reachable even when the auth pipeline is
	// degraded — which is exactly when an operator needs an answer from them —
	// then the composed auth router, then the terminal error handler. See
	// `routes.mts` for what each is and why the order is what it is.
	mountRoutes(app, {
		router: handle.router,
		probes: handle.readinessProbes,
		readinessTimeoutMs: config.http.readinessTimeoutMs,
		metrics,
		logger,
	});
	// Step 5: start the HTTP server.
	// Resolves once the socket is bound (`server_listening`); a port that
	// cannot be bound rejects, and boot fails with that error (`listen.mts`).
	const server = await listen(app, config.http.port, logger);

	// Step 6: Graceful shutdown — handle.dispose() runs reverse-topological
	// per-component cleanup (per A2-β §8.1) plus D-5 LifecycleRegistrar drain
	// (Redis clients, interval timers).
	//
	// #290: in the template rather than a dependency, because "does SIGTERM
	// wait for in-flight requests, and for how long?" has to be answerable
	// from the code you deploy. See `shutdown.mts` for the stated guarantees
	// and for the deadline the previous implementation did not have. Size
	// `drainTimeoutMs` below your orchestrator's kill grace period.
	//
	// #593 slice 7: with federation grants on, cleanup gets the longest refresh
	// tail the configured budgets allow plus a margin — 45 s under the shipped
	// ones — rather than inheriting the drain's ten: the dispose is what waits
	// for a rotated credential's write. The compose files size
	// `stop_grace_period` to cover the drain, this and an exit margin for the
	// shipped budgets; a raised budget raises both.
	installGracefulShutdown(server, {
		logger,
		cleanup: () => handle.dispose(),
		...cleanupAllowanceFor(config),
	});
})();
