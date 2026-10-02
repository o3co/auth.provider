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

/**
 * The standalone composes federation grants from its config.
 *
 * What is under test is the WIRING: which modules the switches select, that
 * the shared Redis client module provides the two slots the Redis stores
 * require, and that the refusals a wrong pairing earns come from the modules
 * themselves. The flows a connection needs are the package's own tests; a
 * connection here would need a live IdP, because the OIDC federation
 * discovers at boot. It also pins what the consent answer accepts under the
 * session module's own CSRF guard, the one the standalone composes.
 */

import { fileURLToPath } from "node:url";
import {
	AppConfigSchema,
	createApp,
	createKeyStoreFactory,
	defineModule,
	InMemoryClientRepository,
	InMemoryUserRepository,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import { standardSmtpMailSenderConfigForTests } from "@o3co/auth-provider-standard/testing";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, type Switches } from "../configPath.mjs";
import { templateReference } from "../modules.mjs";
import { installGracefulShutdown } from "../shutdown.mjs";
import {
	capturedRenames,
	libraryLayers,
	rootSectionsOf,
	sectionsCoreDoesNotDeclare,
} from "./library-references.fixture.mjs";

// The same stand-ins `replica-safety.test.mts` boots under: no socket opens,
// and the shared clients module's readiness probe gets its PONG.
vi.mock("redis", () => ({
	createClient: vi.fn(() => ({
		connect: vi.fn().mockResolvedValue(undefined),
		quit: vi.fn().mockResolvedValue(undefined),
		ping: vi.fn().mockResolvedValue("PONG"),
		on: vi.fn(),
	})),
}));

vi.mock("connect-redis", async () => {
	const { EventEmitter } = await import("node:events");
	return {
		RedisStore: class MockRedisStore extends EventEmitter {
			constructor(_opts: { client: unknown }) {
				super();
			}
			get(): unknown {
				return undefined;
			}
			set(): void {}
			destroy(): void {}
		},
	};
});

vi.mock("ioredis", () => {
	const explicit: Record<string, unknown> = {
		on: () => undefined,
		quit: async () => "OK",
		disconnect: () => undefined,
		ping: async () => "PONG",
	};
	const makeMockRedis = (): object =>
		new Proxy(
			{},
			{
				get(_target, prop) {
					if (typeof prop !== "string" || prop === "then") return undefined;
					if (prop === "duplicate") return makeMockRedis;
					if (prop in explicit) return explicit[prop];
					return async () => null;
				},
			},
		);
	function MockRedis(): object {
		return makeMockRedis();
	}
	return { Redis: MockRedis, default: MockRedis };
});

const configDir = fileURLToPath(new URL("../../config", import.meta.url));
const ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");

/** A single-replica deployment with every shared store on memory, grants off, MFA off. */
const BASE_ENV: Readonly<Record<string, string>> = {
	MFA_MODE: "off",
	KEY_STORE_LOCAL_ALGORITHM: "HS256",
	KEY_STORE_LOCAL_SECRET: "federation-grants-composition.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_STORE_SECRET: "federation-grants-composition-session.at-least-32-bytes.ok",
	SESSION_STORE_SECURE: "false",
	SESSION_STORE_NAME: "auth.session",
	SESSION_STORE_STORAGE_TYPE: "memory",
	ADAPTERS_USER_REPOSITORY: "yaml",
	REDIS_CLIENTS_URL: "redis://redis.test:6379",
	ADAPTERS_USER_SESSION_STORES: "memory",
	ADAPTERS_RATE_LIMITER: "memory",
	ADAPTERS_CODE_REPOSITORY: "memory",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
	ADAPTERS_REPLAY_SEEN_SET: "memory",
	ADAPTERS_FEDERATION_TOKEN_STORE: "memory",
	ADAPTERS_CONSENT_STORE: "none",
	ADAPTERS_FEDERATION_GRANT_STORE: "memory",
	ADAPTERS_FEDERATION_GRANT_INTENT_STORE: "memory",
};

/** The umbrella E2E's shape: every shared store on Redis, more than one replica. */
const ALL_REDIS_ENV: Readonly<Record<string, string>> = {
	...BASE_ENV,
	CORE_DEPLOYMENT_MODE: "multi",
	SESSION_STORE_STORAGE_TYPE: "redis",
	SESSION_STORE_STORAGE_REDIS_URL: "redis://redis.test:6379",
	ADAPTERS_USER_SESSION_STORES: "redis",
	ADAPTERS_RATE_LIMITER: "redis",
	ADAPTERS_CODE_REPOSITORY: "redis",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "redis",
	ADAPTERS_REPLAY_SEEN_SET: "redis",
	ADAPTERS_FEDERATION_TOKEN_STORE: "redis",
	REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY: ENCRYPTION_KEY,
	ADAPTERS_CONSENT_STORE: "redis",
	ADAPTERS_FEDERATION_GRANT_STORE: "redis",
	ADAPTERS_FEDERATION_GRANT_INTENT_STORE: "redis",
};

/** What enabling the feature adds: the switch, and the page boot requires. */
const GRANTS_ON: Readonly<Record<string, string>> = {
	FEDERATION_GRANTS_ENABLED: "true",
	FEDERATION_GRANTS_CONSENT_URL: "/consent/grants",
};

function resolveConfig(env: Record<string, string>): Switches {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	const layers = parseFile(envConfPath, { env })
		.withFallback(parseFile(applicationConfPath, { env }))
		.withFallback(parseFile(fileURLToPath(templateReference()), { env }))
		.withFallback(libraryLayers(env));
	const config = {
		...sectionsCoreDoesNotDeclare(layers),
		...validate(layers, AppConfigSchema),
		...rootSectionsOf(layers, env),
	};
	// The key ring has no environment form (a list of { id, key } is HOCON's);
	// the Redis grant store refuses to construct without one under "required".
	return {
		...config,
		// What the resolution captured of core's renamed variables, which the
		// schema's parse drops.
		"renamed-variables": capturedRenames(env),
		"redis-federation-grant-store": {
			...(config["redis-federation-grant-store"] as object | undefined),
			encryptionKeys: [{ id: "k-test", key: ENCRYPTION_KEY }],
		},
	} as Switches;
}

const testRepositoriesModule = defineModule({
	name: "test:repositories",
	provides: {
		clientRepository: () => new InMemoryClientRepository(new Map()),
		userRepository: () => new InMemoryUserRepository(new Map()),
	},
});

const testKeyStoreModule = defineModule({
	name: "test:key-store",
	requires: ["config"] as const,
	provides: {
		keyStore: async ({ config: c }) => {
			const factory = createKeyStoreFactory();
			registerBuiltinKeyStores(factory);
			return factory.create({
				type: "local",
				...((c as { "key-store"?: { local?: object } })["key-store"]?.local ?? {}),
			});
		},
	},
});

const modulesFor = (config: Switches, memoryOnly = false, environment?: string) =>
	buildModules(config, {
		keyStoreModule: testKeyStoreModule,
		repositoriesModule: testRepositoriesModule,
		...(memoryOnly ? { refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule] } : {}),
		...(environment === undefined ? {} : { environment }),
	});

const boot = (config: Switches, memoryOnly = false, environment?: string) =>
	createApp({
		modules: modulesFor(config, memoryOnly, environment),
		bootstrapComponents: { config, pathResolver: (s) => s },
	});

const names = (config: Switches, memoryOnly = false) =>
	modulesFor(config, memoryOnly).map((m) => m.name);

/**
 * `app.mts`'s shutdown over `handle`, with a server double whose drain ends at
 * once and signals that are not the process's: the handle's own dispose and
 * the allowance it reports.
 */
function shutDown(handle: Awaited<ReturnType<typeof boot>>) {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	};
	const exit = vi.fn();
	const signals = new Map<string, () => void>();
	const server = {
		close: (callback?: (err?: Error) => void) => {
			callback?.();
			return server;
		},
		closeIdleConnections: () => undefined,
		closeAllConnections: () => undefined,
	};
	installGracefulShutdown(server as never, {
		logger: logger as never,
		cleanup: () => handle.dispose(),
		cleanupAllowanceMs: () => handle.cleanupAllowanceMs,
		exit,
		onSignal: (name, handler) => signals.set(name, handler),
		offSignal: (name) => signals.delete(name),
	});
	return { logger, exit, sigterm: () => signals.get("SIGTERM")?.() };
}

/**
 * Work the background registry holds open, as a refresh tail does, until the
 * returned release: the drain waits for it.
 */
const holdTheDrainOpen = (handle: Awaited<ReturnType<typeof boot>>): (() => void) => {
	let release!: () => void;
	handle.components.federationGrantBackground?.register(
		new Promise<void>((resolve) => {
			release = () => resolve();
		}),
	);
	return release;
};

const GRANT_MODULES = [
	"federation-grants",
	"federation-grant-background",
	"core-federation-grant-store-memory",
	"core-federation-grant-intent-store-memory",
	"redis-federation-grant-store",
	"redis-federation-grant-intent-store",
	"subject-revocation-service",
];

/** The message of a boot failure and of the module error it wraps, together. */
const messageChain = (err: unknown): string => {
	const e = err as { message?: string; cause?: { message?: string } };
	return `${e.message ?? ""} ${e.cause?.message ?? ""}`;
};

describe("the standalone composes federation grants from its config", () => {
	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	it("installs nothing of the feature while it is off, whatever the switches say", async () => {
		// Off is the default, and off must cost nothing: no store, no socket, no
		// boot requirement a deployment that never asked for grants would meet.
		const config = resolveConfig({ ...BASE_ENV, ADAPTERS_FEDERATION_GRANT_STORE: "redis" });
		const installed = names(config, true);
		for (const name of GRANT_MODULES) expect(installed).not.toContain(name);
		expect(installed).not.toContain("redis-clients");

		handleRef = await boot(config, true);
		const app = express().use(handleRef.router);
		expect((await request(app).post("/oauth/federation-grants/g/status")).status).toBe(404);
	});

	it("boots on memory stores with no connection, and mounts the routes", async () => {
		const config = resolveConfig({ ...BASE_ENV, ...GRANTS_ON });
		const installed = names(config, true);
		expect(installed).toEqual(
			expect.arrayContaining([
				"federation-grant-background",
				"federation-grants",
				"core-federation-grant-store-memory",
				"core-federation-grant-intent-store-memory",
				"subject-revocation-service",
			]),
		);
		expect(installed).not.toContain("redis-federation-grant-store");
		expect(installed).not.toContain("redis-federation-grant-intent-store");
		// Listed ahead of oauthModule, as the template writes them: the
		// template's choice, since each module parses its own bodies and the
		// order does not change that; the browser half sits after the session
		// middleware by its own `after`.
		expect(installed.indexOf("federation-grants")).toBeLessThan(installed.indexOf("oauth"));

		handleRef = await boot(config, true);
		const app = express().use(handleRef.router);
		// Mounted: the JSON router answers for itself (client authentication),
		// not express's 404.
		expect((await request(app).post("/oauth/federation-grants/g/status")).status).toBe(401);
		expect(handleRef.components.subjectRevocationService).toBeDefined();
		// The connect flow's login trip is the session module's loginEntry,
		// built from the configured login page: the URL connect sends
		// a browser that is not signed in to.
		const page = (config.session as { loginPage: { url: string } }).loginPage.url;
		const back = "https://auth.example/session/federation-grants/connect?request=h";
		expect(handleRef.components.loginEntry?.urlFor(back)).toBe(
			`${page}${page.includes("?") ? "&" : "?"}redirect_to=${encodeURIComponent(back)}`,
		);
	});

	it("selects the Redis stores under the all-Redis environment, provides their clients, and boots under multi", async () => {
		const config = resolveConfig({ ...ALL_REDIS_ENV, ...GRANTS_ON });
		const modules = modulesFor(config);
		const installed = modules.map((m) => m.name);
		expect(installed).toEqual(
			expect.arrayContaining([
				"redis-federation-grant-store",
				"redis-federation-grant-intent-store",
			]),
		);
		expect(installed).not.toContain("core-federation-grant-store-memory");
		expect(installed).not.toContain("core-federation-grant-intent-store-memory");
		const clients = modules.find((m) => m.name === "redis-clients");
		expect(Object.keys(clients?.provides ?? {})).toEqual(
			expect.arrayContaining(["federationGrantStoreClient", "federationGrantIntentStoreClient"]),
		);

		handleRef = await boot(config);
		expect(handleRef.components.federationGrantStore?.kind).toBe("redis");
	});

	it("gives cleanup the documented 45 seconds under the shipped budgets, not the drain's ten", async () => {
		// reference.conf's budgets: 25 s + 3 s + 5 s, plus the 12-second margin.
		handleRef = await boot(resolveConfig({ ...BASE_ENV, ...GRANTS_ON }), true);
		expect(handleRef.cleanupAllowanceMs).toBe(45_000);

		vi.useFakeTimers();
		const release = holdTheDrainOpen(handleRef);
		try {
			const { logger, exit, sigterm } = shutDown(handleRef);
			sigterm();
			await vi.advanceTimersByTimeAsync(44_999);
			expect(exit).not.toHaveBeenCalled();
			await vi.advanceTimersByTimeAsync(1);
			expect(logger.error).toHaveBeenCalledWith(
				{ cleanupTimeoutMs: 45_000 },
				"shutdown_cleanup_timed_out",
			);
			expect(exit).toHaveBeenCalledExactlyOnceWith(1);
		} finally {
			release();
			vi.useRealTimers();
		}
	});

	it("grows the allowance with a raised refresh budget", async () => {
		const shipped = resolveConfig({ ...BASE_ENV, ...GRANTS_ON });
		// The lock must outlive the raised hard timeout, or boot refuses first.
		const raised = {
			...shipped,
			"federation-grants": {
				...shipped["federation-grants"],
				upstreamHardTimeoutMs: 60_000,
				refreshLockTtlMs: 65_000,
			},
		} as Switches;
		handleRef = await boot(raised, true);
		expect(handleRef.cleanupAllowanceMs).toBe(60_000 + 3_000 + 5_000 + 12_000);

		vi.useFakeTimers();
		const release = holdTheDrainOpen(handleRef);
		try {
			const { logger, exit, sigterm } = shutDown(handleRef);
			sigterm();
			await vi.advanceTimersByTimeAsync(79_999);
			expect(exit).not.toHaveBeenCalled();
			await vi.advanceTimersByTimeAsync(1);
			expect(logger.error).toHaveBeenCalledWith(
				{ cleanupTimeoutMs: 80_000 },
				"shutdown_cleanup_timed_out",
			);
		} finally {
			release();
			vi.useRealTimers();
		}
	});

	it("reports no allowance while the feature is off, and cleanup's budget is the drain's ten seconds", async () => {
		handleRef = await boot(resolveConfig(BASE_ENV), true);
		expect(handleRef.cleanupAllowanceMs).toBeUndefined();
		const { logger, exit, sigterm } = shutDown(handleRef);
		sigterm();
		await vi.waitFor(() => expect(exit).toHaveBeenCalledExactlyOnceWith(0));
		expect(logger.info).toHaveBeenCalledWith(
			{ drainTimeoutMs: 10_000, cleanupTimeoutMs: 10_000 },
			"shutdown_draining",
		);
	});

	it("covers a tail registered after the shutdown was installed", async () => {
		handleRef = await boot(resolveConfig(BASE_ENV), true);
		const { logger, sigterm } = shutDown(handleRef);
		handleRef.components.lifecycleRegistrar?.register(async () => {}, { tailMs: 60_000 });
		sigterm();
		expect(logger.info).toHaveBeenCalledWith(
			{ drainTimeoutMs: 10_000, cleanupTimeoutMs: 60_000 },
			"shutdown_draining",
		);
	});

	it("adds the shared Redis client for the grant stores alone", () => {
		// Every other adapter on memory and the RT family store overridden: only
		// the two grant switches ask for Redis, and that is enough.
		const config = resolveConfig({
			...BASE_ENV,
			...GRANTS_ON,
			ADAPTERS_FEDERATION_GRANT_STORE: "redis",
			ADAPTERS_FEDERATION_GRANT_INTENT_STORE: "redis",
		});
		expect(names(config, true)).toContain("redis-clients");
	});

	it.each([
		["ADAPTERS_FEDERATION_GRANT_STORE", "core-federation-grant-store-memory"],
		["ADAPTERS_FEDERATION_GRANT_INTENT_STORE", "core-federation-grant-intent-store-memory"],
	])("%s=memory is refused under multi, naming %s", async (variable, module) => {
		const config = resolveConfig({ ...ALL_REDIS_ENV, ...GRANTS_ON, [variable]: "memory" });
		await expect(boot(config)).rejects.toMatchObject({
			name: "BootError",
			reason: "replica-unsafe-adapter",
			details: { modules: [module] },
		});
	});

	it.each([
		[
			"a __Secure- name that is not secure",
			"name",
			{ SESSION_STORE_NAME: "__Secure-auth.session", SESSION_STORE_SECURE: "false" },
			/__Secure- prefix requires session-store\.secure=true/,
		],
		[
			"a name that is not an RFC 6265 token",
			"name",
			{ SESSION_STORE_NAME: "auth session" },
			/is not a cookie name \(an RFC 6265 token\)/,
		],
		[
			"a domain that is a URL",
			"domain",
			{ SESSION_STORE_NAME: "auth.session", SESSION_STORE_DOMAIN: "https://auth.example.com" },
			/is not a cookie domain/,
		],
	])(
		"refuses at validation a session cookie no browser keeps, %s, naming session-store.%s, with or without the subject revocation service",
		async (_what, key, cookie, refusal) => {
			for (const grants of [{}, GRANTS_ON]) {
				const caught = await boot(resolveConfig({ ...BASE_ENV, ...grants, ...cookie }), true).then(
					async (handle) => {
						await handle.dispose();
						return undefined;
					},
					(err: unknown) => err,
				);
				expect(caught).toMatchObject({
					name: "BootError",
					reason: "config-validation-failed",
					stage: "validateManifests",
					details: {
						issues: [expect.objectContaining({ path: ["session-store", key] })],
					},
				});
				expect(messageChain(caught)).toMatch(refusal);
			}
		},
	);

	it.each([
		// `config/application.conf`'s own cookie: `__Host-`, secure, host-only.
		["the template's default", { SESSION_STORE_NAME: undefined, SESSION_STORE_SECURE: undefined }],
		// `.env.example`'s plain-HTTP pair, which `make dev` runs with.
		[".env.example's", { SESSION_STORE_NAME: "auth.sid", SESSION_STORE_SECURE: "false" }],
		// `docker-compose.production.yml` restores the default name, secure.
		[
			"the production compose file's",
			{ SESSION_STORE_NAME: "__Host-auth.session", SESSION_STORE_SECURE: "true" },
		],
		// o3co/auth's `tests/docker-compose.yml`, which the umbrella E2E boots.
		["the umbrella E2E's", { SESSION_STORE_NAME: "auth.session", SESSION_STORE_SECURE: "false" }],
	])(
		"boots %s session cookie, with or without the subject revocation service",
		async (_what, cookie) => {
			const env: Record<string, string> = { ...BASE_ENV };
			for (const [name, value] of Object.entries(cookie)) {
				if (value === undefined) delete env[name];
				else env[name] = value;
			}
			for (const grants of [{}, GRANTS_ON]) {
				handleRef = await boot(resolveConfig({ ...env, ...grants }), true);
				expect(handleRef.routes.map((r) => r.contribution.id)).toContain("session-middleware");
				await handleRef.dispose();
				handleRef = undefined;
			}
		},
	);

	it("refuses Redis grants beside memory user-session stores, naming the boundary", async () => {
		// The grants would outlive the process; the boundary that ends them
		// would not. The routes module refuses the pairing on a single replica
		// too, and its message names the remedy.
		const config = resolveConfig({
			...BASE_ENV,
			...GRANTS_ON,
			ADAPTERS_FEDERATION_GRANT_STORE: "redis",
			ADAPTERS_FEDERATION_GRANT_INTENT_STORE: "memory",
		});
		let error: unknown;
		try {
			handleRef = await boot(config);
		} catch (caught) {
			error = caught;
		}
		expect(messageChain(error)).toMatch(/subject boundary is kept in "memory"/);
	});

	it("hands the Redis grant store the environment the config was selected by, so its plaintext guard reads it", async () => {
		// The federation-token store's guard reads `environment` beside
		// NODE_ENV so that CONFIG_ENV=production is production to it; the grant
		// store's must too, or a deployment selecting its config by CONFIG_ENV
		// with NODE_ENV unset would keep its refresh tokens in plaintext.
		const config = resolveConfig({
			...BASE_ENV,
			...GRANTS_ON,
			ADAPTERS_USER_SESSION_STORES: "redis",
			ADAPTERS_FEDERATION_GRANT_STORE: "redis",
			REDIS_FEDERATION_GRANT_STORE_ENCRYPTION_MODE: "allow-plaintext",
		});
		let error: unknown;
		try {
			// Under production the template installs the SMTP sender's module,
			// whose section the package's builder carries.
			handleRef = await boot(
				{ ...config, ...standardSmtpMailSenderConfigForTests() },
				false,
				"production",
			);
		} catch (caught) {
			error = caught;
		}
		expect(messageChain(error)).toMatch(/federation-grants[\s\S]*allow-plaintext[\s\S]*production/);
		// The same config under the test environment boots: it is the name that
		// selected the config, not a hard refusal of plaintext.
		handleRef = await boot(config);
		expect(handleRef.components.federationGrantStore?.kind).toBe("redis");
	});

	it("keeps Redis grants beside memory intents on a single replica", async () => {
		// A restart loses flows in progress and no established grant.
		const config = resolveConfig({
			...BASE_ENV,
			...GRANTS_ON,
			ADAPTERS_USER_SESSION_STORES: "redis",
			ADAPTERS_FEDERATION_GRANT_STORE: "redis",
			ADAPTERS_FEDERATION_GRANT_INTENT_STORE: "memory",
		});
		handleRef = await boot(config);
		expect(handleRef.components.federationGrantStore?.kind).toBe("redis");
		expect(names(config)).toContain("core-federation-grant-intent-store-memory");
	});
});

describe("the browser consent route parses its own body, with sessionModule listed ahead of it", () => {
	// `sessionModule`'s routers are mounted at `/session`, the prefix the
	// federation grants browser half mounts under too. If their parsers ran
	// for every request beneath `/session`, then with `sessionModule` listed
	// first the consent route's body would arrive parsed, past its 16 KiB
	// bound, its throttle-then-parse order and its JSON refusals.
	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	/** The standalone's modules, with `sessionModule` moved ahead of the grant modules. */
	const sessionFirst = (config: Switches) => {
		const modules = modulesFor(config, true);
		const session = modules.find((m) => m.name === "session");
		if (session === undefined) throw new Error("sessionModule is not in the standalone's list");
		const rest = modules.filter((m) => m !== session);
		const at = rest.findIndex((m) => m.name.startsWith("federation-grant"));
		return [...rest.slice(0, at), session, ...rest.slice(at)];
	};

	const bootSessionFirst = async () => {
		const config = resolveConfig({ ...BASE_ENV, ...GRANTS_ON });
		handleRef = await createApp({
			modules: sessionFirst(config),
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		return express().use(handleRef.router);
	};

	const CONSENT = "/session/federation-grants/consent";

	it("refuses a body over 16 KiB with the route's own 413", async () => {
		const app = await bootSessionFirst();

		const res = await request(app)
			.post(CONSENT)
			.set("Content-Type", "application/json")
			.send(JSON.stringify({ challenge: "c", decision: "accept", pad: "a".repeat(40 * 1024) }));

		expect(res.status).toBe(413);
		expect(res.body).toEqual({ error: "invalid_request", error_description: "body_too_large" });
	});

	it("refuses malformed JSON with the route's own 400", async () => {
		const app = await bootSessionFirst();

		const res = await request(app)
			.post(CONSENT)
			.set("Content-Type", "application/json")
			.send("{not json");

		expect(res.status).toBe(400);
		expect(res.body).toEqual({ error: "invalid_request", error_description: "malformed_body" });
		expect(res.headers["cache-control"]).toContain("no-store");
	});
});

describe("the grants consent answer is held to the session module's CSRF guard", () => {
	// No browser is signed in here: an answer the guard accepts reaches the
	// route's own `401 login_required`, and one it refuses stops at its `403`.
	const CONSENT = "/session/federation-grants/consent";
	const ISSUER_ORIGIN = "https://auth.test";
	const SIBLING = "https://account.auth.test";
	/** What the deployment's proxy forwards: the origin the browser addressed. */
	const FORWARDED = { "X-Forwarded-Proto": "https", "X-Forwarded-Host": "auth.test" };
	const CROSS_SITE = { error: "invalid_request", error_description: "cross-site answer refused" };
	const NO_ORIGIN = {
		error: "invalid_request",
		error_description: "no origin and no valid csrf token",
	};

	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	/** The standalone with grants on and `SIBLING` on `session.csrf.trustedOrigins`, behind its proxy. */
	const bootTrustingSibling = async () => {
		const config = resolveConfig({ ...BASE_ENV, ...GRANTS_ON });
		const session = config.session as { csrf?: object };
		const trusting = {
			...config,
			session: { ...session, csrf: { ...session.csrf, trustedOrigins: [SIBLING] } },
		} as Switches;
		handleRef = await boot(trusting, true);
		return express().set("trust proxy", "loopback").use(handleRef.router);
	};

	/** The token `GET /session/csrf` hands out, and the `Cookie` header that carries it back. */
	const tokenFrom = async (app: express.Express) => {
		const issued = await request(app).get("/session/csrf").set(FORWARDED);
		expect(issued.status).toBe(200);
		const [cookie] = (issued.headers["set-cookie"] as unknown as string[])[0]?.split(";") ?? [];
		return { token: issued.body.csrf_token as string, cookie: cookie ?? "" };
	};

	const answer = (
		app: express.Express,
		headers: Readonly<Record<string, string>>,
		body: Readonly<Record<string, string>> = {},
	) =>
		request(app)
			.post(CONSENT)
			.set(FORWARDED)
			.set({ ...headers })
			.type("form")
			.send({ challenge: "c", decision: "accept", ...body });

	it("accepts an Origin that is the request's own, as the proxy forwards it", async () => {
		const app = await bootTrustingSibling();
		const res = await answer(app, { Origin: ISSUER_ORIGIN, "Sec-Fetch-Site": "same-origin" });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
	});

	it("refuses Origin: null, even with the token GET /session/csrf hands out", async () => {
		const app = await bootTrustingSibling();
		const { token, cookie } = await tokenFrom(app);
		const res = await answer(
			app,
			{ Origin: "null", "Sec-Fetch-Site": "same-origin", Cookie: cookie },
			{ csrf_token: token },
		);
		expect(res.status).toBe(403);
		expect(res.body).toEqual(CROSS_SITE);
	});

	it("refuses an answer with no Origin, no Referer and no token, and accepts one echoing the token GET /session/csrf hands out", async () => {
		const app = await bootTrustingSibling();
		const refused = await answer(app, { "Sec-Fetch-Site": "same-origin" });
		expect(refused.status).toBe(403);
		expect(refused.body).toEqual(NO_ORIGIN);
		const { token, cookie } = await tokenFrom(app);
		const accepted = await answer(app, { Cookie: cookie }, { csrf_token: token });
		expect(accepted.status).toBe(401);
		expect(accepted.body.error).toBe("login_required");
	});

	it("accepts an answer with no Origin that echoes the token GET /session/csrf hands out in the x-csrf-token header", async () => {
		const app = await bootTrustingSibling();
		const { token, cookie } = await tokenFrom(app);
		const res = await answer(app, { Cookie: cookie, "x-csrf-token": token });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
	});

	it("refuses an answer with no Origin whose token is not its cookie's", async () => {
		const app = await bootTrustingSibling();
		const first = await tokenFrom(app);
		const second = await tokenFrom(app);
		const res = await answer(app, { Cookie: first.cookie }, { csrf_token: second.token });
		expect(res.status).toBe(403);
		expect(res.body).toEqual(NO_ORIGIN);
	});

	it("accepts an origin on session.csrf.trustedOrigins sending Sec-Fetch-Site: same-site", async () => {
		const app = await bootTrustingSibling();
		const res = await answer(app, { Origin: SIBLING, "Sec-Fetch-Site": "same-site" });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
	});

	it("refuses a cross-site answer, even with the token", async () => {
		const app = await bootTrustingSibling();
		const { token, cookie } = await tokenFrom(app);
		const res = await answer(
			app,
			{ Origin: "https://evil.test", "Sec-Fetch-Site": "cross-site", Cookie: cookie },
			{ csrf_token: token },
		);
		expect(res.status).toBe(403);
		expect(res.body).toEqual(CROSS_SITE);
	});
});
