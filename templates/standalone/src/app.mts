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
import { buildModules } from "./buildModules.mjs";
import {
	expectedSessionRequirements,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
} from "./configPath.mjs";
import { listen } from "./listen.mjs";
import { createAppLogger } from "./logger.mjs";
import { createMetrics } from "./metrics.mjs";
import { mountRoutes } from "./routes.mjs";
import { cleanupAllowanceFor, installGracefulShutdown } from "./shutdown.mjs";

// Step 1: the configuration, in two phases (`configPath.mts`; template
// README, "Environment-specific config overlay").
// ENV = CONFIG_ENV || NODE_ENV || "development"; missing {ENV}.conf is fatal.
const env = process.env.CONFIG_ENV || process.env.NODE_ENV || "development";
const configDir = new URL("../config/", import.meta.url);
const configDirPath = fileURLToPath(configDir);
const { applicationConfPath, envConfPath } = resolveConfigPaths(configDirPath, env);
// Read once, so both phases read the same thing.
const own = readOwnLayers([envConfPath, applicationConfPath]);
// Phase one: what the template reads before it knows its modules, only for
// those choices, and for what the composition expects of session admission
// (`expectedSessionRequirements`): the configuration's list, with `mfa` added
// when `mfa.mode`, which the template reads itself (`readMfaMode`), asks for a
// second factor.
const switches: AppConfig = readSwitches(own);

// Built from config so its level is operator-controlled, and wired into
// `bootstrapComponents` so every module that declares `optional: ["logger"]`
// logs through it rather than its own default (template README, "Logging").
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

	// Step 3: boot the auth pipeline. `buildModules` is the single source of
	// truth for the module list and its order; `bootstrapComponents` carries
	// only host-environment values, every other component comes from the
	// modules. `environment` is the name the config was selected by: the Redis
	// federation-token store's plaintext guard reads it as well as NODE_ENV,
	// so `CONFIG_ENV=production` is production to the guard too.
	//
	// Phase two: `createApp` parses the configuration as resolved once, with
	// every loaded module's schema, stripping no section (`configPath.mts`).
	// From here on the template reads the parsed configuration.
	const modules = buildModules(switches, { environment: env, logger });
	const handle = await createApp({
		modules,
		bootstrapComponents: {
			config: resolveForBoot(own, modules, expectedSessionRequirements(switches)),
			pathResolver: import.meta.resolve,
			logger,
		},
	});
	const config = handle.components.config;
	if (config === undefined) throw new Error("createApp booted without the parsed configuration");
	// `false` | `true` | a hop count | a list of IPs / CIDR ranges / named
	// ranges: the shapes `trust proxy` understands, validated at boot so a
	// typo'd range fails there rather than silently never matching. Prefer
	// naming the proxy: `true` believes a forwarded client address from anyone
	// who can reach this process, and every IP-keyed rate limit buckets on
	// `req.ip`.
	app.set("trust proxy", config.http.trustProxy);

	// Step 4: the host routes (liveness, readiness, metrics), then the composed
	// auth router, then the terminal error handler; `routes.mts` says why in
	// that order.
	mountRoutes(app, {
		router: handle.router,
		probes: handle.readinessProbes,
		readinessTimeoutMs: config.http.readinessTimeoutMs,
		metrics,
		logger,
	});
	// Step 5: start the HTTP server. A port that cannot be bound fails boot
	// with that error (`listen.mts`).
	const server = await listen(app, config.http.port, logger);

	// Step 6: graceful shutdown (`shutdown.mts`). Size `drainTimeoutMs` below
	// your orchestrator's kill grace period. With federation grants on, cleanup
	// gets the longest refresh tail the configured budgets allow plus a margin
	// (45 s under the shipped ones) rather than the drain's ten; the template
	// README, "Shutdown guarantees", sizes the grace period for it.
	installGracefulShutdown(server, {
		logger,
		cleanup: () => handle.dispose(),
		...cleanupAllowanceFor(config),
	});
})();
