// composed-entry.mjs — harness code, not legacy code.
//
// Boots the legacy standalone template (v0.17.0) the way its dist/app.mjs
// does, plus the extra packages named in LEGACY_EXTRA. Imports the legacy
// build by absolute file URL; changes nothing in the checkout.
//
//   LEGACY_DIR          the legacy checkout (required)
//   LEGACY_EXTRA        comma list of: mtls, github, google, apple, webauthn, webauthn-mfa,
//                       token-exchange, device-grant, dpop (optional)
//   LEGACY_GITHUB_BASE  a fake GitHub's base: github.com and api.github.com
//                       are fetched there instead (optional)
//   LEGACY_GOOGLE_BASE  a fake Google's base, for accounts.google.com,
//                       oauth2.googleapis.com and www.googleapis.com (optional)
//   LEGACY_APPLE_BASE   a fake Apple's base, for appleid.apple.com (optional)
//
// Every other variable (HTTP_PORT, CONFIG_ENV, REDIS_CLIENTS_URL, ADAPTERS_*,
// ...) is read by the legacy code exactly as under `node dist/app.mjs`.

import { createRequire } from "node:module";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { extras as packagesOf } from "./extras.mjs";

const legacyDir = process.env.LEGACY_DIR;
if (!legacyDir) throw new Error("LEGACY_DIR is not set");
const standaloneDir = join(legacyDir, "templates", "standalone");

const KNOWN = Object.keys(packagesOf);
const extras = (process.env.LEGACY_EXTRA ?? "")
	.split(",")
	.map((name) => name.trim())
	.filter((name) => name !== "");
const unknown = extras.filter((name) => !KNOWN.includes(name));
if (unknown.length > 0) {
	throw new Error(
		`LEGACY_EXTRA names unknown packages: ${unknown.join(", ")} (known: ${KNOWN.join(", ")})`,
	);
}

// The standalone build's own files, and the workspace packages' built entries.
// Paths are the real ones (pnpm's node_modules/@o3co/* are symlinks to
// packages/*), so these are the same module instances the build imports.
const fromStandalone = (file) => import(pathToFileURL(join(standaloneDir, "dist", file)).href);
const fromPackage = (name) =>
	import(pathToFileURL(join(legacyDir, "packages", name, "dist", "index.mjs")).href);
// express is CommonJS; resolve it the way the build does, from the template.
const requireFromStandalone = createRequire(join(standaloneDir, "package.json"));
const express = (await import(pathToFileURL(requireFromStandalone.resolve("express")).href))
	.default;

const core = await fromPackage("core");
const { buildModules } = await fromStandalone("buildModules.mjs");
const {
	configDefaultsFor,
	readLogging,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
} = await fromStandalone("configPath.mjs");
const { listen } = await fromStandalone("listen.mjs");
const { createAppLogger } = await fromStandalone("logger.mjs");
const { createMetrics } = await fromStandalone("metrics.mjs");
const { mountRoutes } = await fromStandalone("routes.mjs");
const { securityHeaders } = await fromStandalone("securityHeaders.mjs");
const { installGracefulShutdown } = await fromStandalone("shutdown.mjs");

// The type modules fix their upstream's hosts in code; their `fetch` option is the one way in.
// Where a fake's base is given, requests to those hosts go to it, path and query kept.
const fetchingAt = (hosts, base) =>
	base
		? {
				fetch: (url, init) => {
					const asked = new URL(String(url));
					if (!hosts.includes(asked.hostname)) return fetch(url, init);
					return fetch(new URL(`${asked.pathname}${asked.search}`, base), init);
				},
			}
		: undefined;

// The modules each extra adds. Each package does nothing until its section
// says so (see the settings each needs); this only installs it.
// The extras whose module takes the place of the build's own of the same name.
const REPLACING = ["google"];
const EXTRA_MODULES = {
	mtls: ([mtls]) => [mtls.mtlsModule],
	github: ([github]) => [
		github.githubFederationTypeModule(
			fetchingAt(["github.com", "api.github.com"], process.env.LEGACY_GITHUB_BASE),
		),
	],
	// The build loads Google's type already, without `fetch`; this one takes its place.
	google: ([google]) => [
		google.googleFederationTypeModule(
			fetchingAt(
				["accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"],
				process.env.LEGACY_GOOGLE_BASE,
			),
		),
	],
	apple: ([apple]) => [
		apple.appleFederationTypeModule(
			fetchingAt(["appleid.apple.com"], process.env.LEGACY_APPLE_BASE),
		),
	],
	dpop: ([dpop]) => [dpop.dpopModule],
	"token-exchange": ([exchange]) => [exchange.tokenExchangeModule],
	"device-grant": ([device]) => [
		device.deviceAuthorizationGrantModule,
		core.memoryDeviceCodeStoreModule,
	],
	"webauthn-mfa": ([webauthn]) => [webauthn.webauthnMfaFactorModule],
	webauthn: ([webauthn]) => {
		return [
			webauthn.webauthnModule,
			core.memoryWebAuthnCredentialStoreModule,
			core.memoryChallengeStoreModule,
			core.defaultChallengeCeremonyModule, // needs replaySeenSet: the build installs one
			// No package ships a GrantPolicyHook and the webauthn grant refuses to
			// build without one. This one allows and narrows nothing; it fills the
			// grantPolicy slot for every grant, not only webauthn's.
			core.defineModule({
				name: "composed-allow-grant-policy",
				provides: {
					grantPolicy: () => ({
						kind: "composed-allow",
						evaluate: async () => ({ outcome: "allow" }),
					}),
				},
			}),
			// Bridges the browser session to req.webauthnSubject for registration.
			webauthn.webauthnSessionSubjectModule({
				subjectFor: (session) => ({
					userId: session.sub,
					...(typeof session.claims?.email === "string" ? { userName: session.claims.email } : {}),
					...(typeof session.claims?.name === "string"
						? { userDisplayName: session.claims.name }
						: {}),
				}),
			}),
		];
	},
};

// app.mjs step 1: configuration, phase one.
const env = process.env.CONFIG_ENV || process.env.NODE_ENV || "development";
const configDirPath = join(standaloneDir, "config");
const { applicationConfPath, envConfPath } = resolveConfigPaths(configDirPath, env);
const own = readOwnLayers([envConfPath, applicationConfPath]);
const switches = readSwitches(own);
const logger = createAppLogger(readLogging(own));

// app.mjs step 2: express, security headers, metrics.
const app = express();
app.use(securityHeaders());
const metrics = createMetrics();
app.use(metrics.middleware);

// app.mjs step 3: the module list, then the extras appended (before the
// configuration is resolved, so their reference.conf and schemas take part).
const modules = buildModules(switches, { environment: env });
for (const name of extras) {
	const loaded = await Promise.all(packagesOf[name].map(fromPackage));
	for (const module of EXTRA_MODULES[name](loaded)) {
		const at = modules.findIndex((m) => m.name === module.name);
		if (at < 0) modules.push(module);
		else if (REPLACING.includes(name)) modules[at] = module;
	}
}
const handle = await core.createApp({
	modules,
	bootstrapComponents: {
		config: resolveForBoot(own, modules, switches),
		configDefaults: configDefaultsFor(modules),
		pathResolver: import.meta.resolve, // as app.mjs passes; nothing in v0.17.0 reads it
		logger,
	},
});
const { httpSettings, httpHostSettings } = handle.components;
if (httpSettings === undefined || httpHostSettings === undefined) {
	throw new Error("createApp booted without the http module's settings");
}
app.set("trust proxy", httpSettings.trustProxy);

// app.mjs step 4: host routes, the auth router, the error handler.
mountRoutes(app, {
	router: handle.router,
	probes: handle.readinessProbes,
	readinessTimeoutMs: httpHostSettings.readinessTimeoutMs,
	metrics,
	logger,
});

// app.mjs step 5: listen on the http module's port (HTTP_PORT).
const server = await listen(app, httpHostSettings.port, logger);

// app.mjs step 6: graceful shutdown.
installGracefulShutdown(server, {
	logger,
	cleanup: () => handle.dispose(),
	cleanupAllowanceMs: () => handle.cleanupAllowanceMs,
});
logger.info({ extras }, "composed_entry_extras");
