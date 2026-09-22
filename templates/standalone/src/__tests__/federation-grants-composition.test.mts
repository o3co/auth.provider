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
 * #593 slice 7 — the standalone composes federation grants from its config.
 *
 * What is under test is the WIRING: which modules the switches select, that
 * the shared Redis client module provides the two slots the Redis stores
 * require, and that the refusals a wrong pairing earns come from the modules
 * themselves. The flows a connection needs are the package's own tests; a
 * connection here would need a live IdP, because the OIDC federation
 * discovers at boot.
 */

import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	AppConfigSchema,
	createApp,
	createKeyStoreFactory,
	defineModule,
	InMemoryClientRepository,
	InMemoryUserRepository,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

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

/** A single-replica deployment with every shared store on memory, grants off. */
const BASE_ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ALGORITHM: "HS256",
	OAUTH_JWT_SECRET: "federation-grants-composition.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "federation-grants-composition-session.at-least-32-bytes.ok",
	SESSION_SECURE: "false",
	SESSION_NAME: "auth.session",
	SESSION_STORAGE_TYPE: "memory",
	CLIENT_USER_TYPE: "yaml",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis.test:6379",
	USER_SESSION_STORES_ADAPTER: "memory",
	RATE_LIMITER_ADAPTER: "memory",
	OAUTH_CODE_ADAPTER: "memory",
	ACCESS_TOKEN_DENYLIST_ADAPTER: "memory",
	REPLAY_SEEN_SET_ADAPTER: "memory",
	FEDERATION_TOKEN_STORE_TYPE: "memory",
	CONSENT_STORE_ADAPTER: "none",
	FEDERATION_GRANT_STORE_ADAPTER: "memory",
	FEDERATION_GRANT_INTENT_STORE_ADAPTER: "memory",
};

/** The umbrella E2E's shape: every shared store on Redis, more than one replica. */
const ALL_REDIS_ENV: Readonly<Record<string, string>> = {
	...BASE_ENV,
	DEPLOYMENT_MODE: "multi",
	SESSION_STORAGE_TYPE: "redis",
	SESSION_STORAGE_REDIS_URL: "redis://redis.test:6379",
	USER_SESSION_STORES_ADAPTER: "redis",
	RATE_LIMITER_ADAPTER: "redis",
	OAUTH_CODE_ADAPTER: "redis",
	ACCESS_TOKEN_DENYLIST_ADAPTER: "redis",
	REPLAY_SEEN_SET_ADAPTER: "redis",
	FEDERATION_TOKEN_STORE_TYPE: "redis",
	REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY: ENCRYPTION_KEY,
	CONSENT_STORE_ADAPTER: "redis",
	FEDERATION_GRANT_STORE_ADAPTER: "redis",
	FEDERATION_GRANT_INTENT_STORE_ADAPTER: "redis",
};

/** What enabling the feature adds: the switch, and the page boot requires. */
const GRANTS_ON: Readonly<Record<string, string>> = {
	FEDERATION_GRANTS_ENABLED: "true",
	FEDERATION_GRANTS_CONSENT_URL: "/consent/grants",
};

function resolveConfig(env: Record<string, string>): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	const config = validate(
		parseFile(envConfPath, { env })
			.withFallback(parseFile(applicationConfPath, { env }))
			.withFallback(parseFile(resolveLibraryReferenceConfPath(), { env })),
		AppConfigSchema,
	);
	// The key ring has no environment form (a list of { id, key } is HOCON's);
	// the Redis grant store refuses to construct without one under "required".
	return {
		...config,
		federationGrants: {
			...config.federationGrants,
			encryptionKeys: [{ id: "k-test", key: ENCRYPTION_KEY }],
		},
	} as AppConfig;
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
				...((c as AppConfig).oauth.jwt.signingKey.local ?? {}),
			});
		},
	},
});

const modulesFor = (config: AppConfig, memoryOnly = false) =>
	buildModules(config, {
		keyStoreModule: testKeyStoreModule,
		repositoriesModule: testRepositoriesModule,
		...(memoryOnly ? { refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule] } : {}),
	});

const boot = (config: AppConfig, memoryOnly = false) =>
	createApp({
		modules: modulesFor(config, memoryOnly),
		bootstrapComponents: { config, pathResolver: (s) => s },
	});

const names = (config: AppConfig, memoryOnly = false) =>
	modulesFor(config, memoryOnly).map((m) => m.name);

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

describe("#593 slice 7: the standalone composes federation grants from its config", () => {
	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	it("installs nothing of the feature while it is off, whatever the switches say", async () => {
		// Off is the default, and off must cost nothing: no store, no socket, no
		// boot requirement a deployment that never asked for grants would meet.
		const config = resolveConfig({ ...BASE_ENV, FEDERATION_GRANT_STORE_ADAPTER: "redis" });
		const installed = names(config, true);
		for (const name of GRANT_MODULES) expect(installed).not.toContain(name);
		expect(installed).not.toContain("standalone:redis-clients");

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
		// The routes precede oauthModule's body parsers (the package README's
		// mounting-order rule), and the browser half sits after the session
		// middleware by its own `after`.
		expect(installed.indexOf("federation-grants")).toBeLessThan(installed.indexOf("oauth"));

		handleRef = await boot(config, true);
		const app = express().use(handleRef.router);
		// Mounted: the JSON router answers for itself (client authentication),
		// not express's 404.
		expect((await request(app).post("/oauth/federation-grants/g/status")).status).toBe(401);
		expect(handleRef.components.subjectRevocationService).toBeDefined();
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
		const clients = modules.find((m) => m.name === "standalone:redis-clients");
		expect(Object.keys(clients?.provides ?? {})).toEqual(
			expect.arrayContaining(["federationGrantStoreClient", "federationGrantIntentStoreClient"]),
		);

		handleRef = await boot(config);
		expect(handleRef.components.federationGrantStore?.kind).toBe("redis");
	});

	it("adds the shared Redis client for the grant stores alone", () => {
		// Every other adapter on memory and the RT family store overridden: only
		// the two grant switches ask for Redis, and that is enough.
		const config = resolveConfig({
			...BASE_ENV,
			...GRANTS_ON,
			FEDERATION_GRANT_STORE_ADAPTER: "redis",
			FEDERATION_GRANT_INTENT_STORE_ADAPTER: "redis",
		});
		expect(names(config, true)).toContain("standalone:redis-clients");
	});

	it.each([
		["FEDERATION_GRANT_STORE_ADAPTER", "core-federation-grant-store-memory"],
		["FEDERATION_GRANT_INTENT_STORE_ADAPTER", "core-federation-grant-intent-store-memory"],
	])("%s=memory is refused under multi, naming %s", async (variable, module) => {
		const config = resolveConfig({ ...ALL_REDIS_ENV, ...GRANTS_ON, [variable]: "memory" });
		await expect(boot(config)).rejects.toMatchObject({
			name: "BootError",
			reason: "replica-unsafe-adapter",
			details: { modules: [module] },
		});
	});

	it("refuses Redis grants beside memory user-session stores, naming the boundary (D13)", async () => {
		// The grants would outlive the process; the boundary that ends them
		// would not. The routes module refuses the pairing on a single replica
		// too, and its message names the remedy.
		const config = resolveConfig({
			...BASE_ENV,
			...GRANTS_ON,
			FEDERATION_GRANT_STORE_ADAPTER: "redis",
			FEDERATION_GRANT_INTENT_STORE_ADAPTER: "memory",
		});
		let error: unknown;
		try {
			handleRef = await boot(config);
		} catch (caught) {
			error = caught;
		}
		expect(messageChain(error)).toMatch(/subject boundary is kept in "memory"/);
	});

	it("keeps Redis grants beside memory intents on a single replica", async () => {
		// A restart loses flows in progress and no established grant.
		const config = resolveConfig({
			...BASE_ENV,
			...GRANTS_ON,
			USER_SESSION_STORES_ADAPTER: "redis",
			FEDERATION_GRANT_STORE_ADAPTER: "redis",
			FEDERATION_GRANT_INTENT_STORE_ADAPTER: "memory",
		});
		handleRef = await boot(config);
		expect(handleRef.components.federationGrantStore?.kind).toBe("redis");
		expect(names(config)).toContain("core-federation-grant-intent-store-memory");
	});
});
