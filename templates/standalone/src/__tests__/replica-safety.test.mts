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
 * #455 / #456 — the standalone's own store modules under
 * `deployment.mode = "multi"`, booted the way an operator reaches them: from
 * the shipped HOCON with one environment variable flipped.
 *
 * #455: the replica-safety guard keyed on core's module names, and this
 * template wires its *own* in-memory modules for three of the stores —
 * session stores, the code repository, the federation token store — under
 * names the guard had never heard of. `DEPLOYMENT_MODE=multi` with
 * `USER_SESSION_STORES_ADAPTER=memory` booted, and the refusal the README
 * promises did not fire for exactly the stores that fork per replica the
 * worst. Every memory branch is booted here under `"multi"` and must be
 * refused by name; the all-Redis environment must boot.
 *
 * #456: `federationTokenStore.type = "redis"` was documented and could not
 * boot — the module went through the adapter factory without ever handing
 * the builder a client. The Redis branch now mounts
 * `redisFederationTokenStoreModule` off the shared ioredis socket; the boot
 * below is the test the README sentence never had.
 *
 * ioredis is mocked, as in `device-code-store-client-module.test.mts`: the
 * point is composition and the boot planner's stage-1 verdict, not Redis.
 * Nothing here issues a command.
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
	registerBuiltinKeyStores,
	replicaUnsafeReason,
} from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

vi.mock("ioredis", () => {
	// Every command resolves to nothing. A boot that reached Redis would be a
	// boot doing work at stage 2 that belongs in an integration test; the
	// stand-in only has to be constructible, quit cleanly, and answer `ping`
	// for the readiness probe the shared clients module registers.
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
					// A `then` that is a function would make the instance a
					// thenable and hang anything that awaits it.
					if (typeof prop !== "string" || prop === "then") return undefined;
					if (prop === "duplicate") return makeMockRedis;
					if (prop in explicit) return explicit[prop];
					return async () => null;
				},
			},
		);
	// The template does `new Redis(url, options)`. A plain function that
	// returns an object yields that object under `new`, so no class — and no
	// constructor returning a value — is needed for the stand-in.
	function MockRedis(): object {
		return makeMockRedis();
	}
	return { Redis: MockRedis, default: MockRedis };
});

// config/ is two levels above this test file: src/__tests__/ → src/ → standalone/
const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/** 32 bytes, base64 — what `REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY` carries. */
const ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");

/**
 * The umbrella E2E's shape (`o3co/auth` `tests/docker-compose.yml`), with
 * every shared store on Redis. Each case below flips one variable off this.
 *
 * `SESSION_STORAGE_TYPE=memory` keeps express-session's own store off
 * node-redis; it is not one of the shared stores the guard covers.
 */
const ALL_REDIS_ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ALGORITHM: "HS256",
	OAUTH_JWT_SECRET: "replica-safety-test-secret.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "replica-safety-session-secret.at-least-32-bytes.ok",
	SESSION_SECURE: "false",
	SESSION_NAME: "auth.session",
	SESSION_STORAGE_TYPE: "memory",
	CLIENT_USER_TYPE: "yaml",
	DEPLOYMENT_MODE: "multi",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis.test:6379",
	USER_SESSION_STORES_ADAPTER: "redis",
	RATE_LIMITER_ADAPTER: "redis",
	OAUTH_CODE_ADAPTER: "redis",
	ACCESS_TOKEN_DENYLIST_ADAPTER: "redis",
	FEDERATION_TOKEN_STORE_TYPE: "redis",
	REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY: ENCRYPTION_KEY,
};

function resolveConfig(env: Record<string, string>): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	return validate(
		parseFile(envConfPath, { env })
			.withFallback(parseFile(applicationConfPath, { env }))
			.withFallback(parseFile(resolveLibraryReferenceConfPath(), { env })),
		AppConfigSchema,
	);
}

/** Drops a variable, so the HOCON default takes over. */
function without(env: Record<string, string>, ...names: string[]): Record<string, string> {
	const copy = { ...env };
	for (const name of names) delete copy[name];
	return copy;
}

// The file-system-backed modules are replaced as in `smoke.test.mts`: the
// boot under test is the store wiring, not the client registry on disk.
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

const modulesFor = (config: AppConfig) =>
	buildModules(config, {
		keyStoreModule: testKeyStoreModule,
		repositoriesModule: testRepositoriesModule,
	});

const boot = (config: AppConfig) =>
	createApp({
		modules: modulesFor(config),
		bootstrapComponents: { config, pathResolver: (s) => s },
	});

describe('#455: the standalone\'s memory modules are refused under deployment.mode = "multi"', () => {
	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	const cases: ReadonlyArray<readonly [variable: string, module: string]> = [
		// The template's own modules — the three the guard could not see.
		["USER_SESSION_STORES_ADAPTER", "standalone:in-memory-session-stores"],
		["OAUTH_CODE_ADAPTER", "standalone:in-memory-code-repository"],
		["FEDERATION_TOKEN_STORE_TYPE", "standalone:in-memory-federation-token-store"],
		// Core's, selected by the same kind of switch. The guard knew these by
		// name; pinned so the name table's departure (#455) did not lose them.
		["RATE_LIMITER_ADAPTER", "core-rate-limiter-memory"],
		["ACCESS_TOKEN_DENYLIST_ADAPTER", "core-access-token-denylist-memory"],
	];

	for (const [variable, module] of cases) {
		it(`${variable}=memory is refused, naming ${module}`, async () => {
			const config = resolveConfig({ ...ALL_REDIS_ENV, [variable]: "memory" });
			await expect(boot(config)).rejects.toMatchObject({
				name: "BootError",
				reason: "replica-unsafe-adapter",
				details: { modules: [module] },
			});
		});
	}

	it("names every memory module together when every switch is memory", async () => {
		const config = resolveConfig({
			...ALL_REDIS_ENV,
			USER_SESSION_STORES_ADAPTER: "memory",
			OAUTH_CODE_ADAPTER: "memory",
			FEDERATION_TOKEN_STORE_TYPE: "memory",
			RATE_LIMITER_ADAPTER: "memory",
			ACCESS_TOKEN_DENYLIST_ADAPTER: "memory",
		});
		await expect(boot(config)).rejects.toMatchObject({
			reason: "replica-unsafe-adapter",
			details: {
				modules: expect.arrayContaining(cases.map(([, module]) => module)),
			},
		});
	});

	it("each standalone memory module declares its consequence on its own manifest", () => {
		// The declaration is what the guard reads (#455), so it has to be on
		// the module and it has to say what breaks — the guard quotes it.
		const config = resolveConfig({
			...ALL_REDIS_ENV,
			USER_SESSION_STORES_ADAPTER: "memory",
			OAUTH_CODE_ADAPTER: "memory",
			FEDERATION_TOKEN_STORE_TYPE: "memory",
		});
		const standaloneMemoryModules = modulesFor(config).filter((m) =>
			m.name.startsWith("standalone:in-memory-"),
		);
		expect(standaloneMemoryModules.map((m) => m.name).sort()).toEqual([
			"standalone:in-memory-code-repository",
			"standalone:in-memory-federation-token-store",
			"standalone:in-memory-session-stores",
		]);
		for (const m of standaloneMemoryModules) {
			expect(replicaUnsafeReason(m), m.name).toBeDefined();
			expect((replicaUnsafeReason(m) ?? "").length, m.name).toBeGreaterThan(40);
		}
	});

	it("boots the all-Redis environment, with nothing declaring replica-unsafe state", async () => {
		const config = resolveConfig(ALL_REDIS_ENV);
		for (const m of modulesFor(config)) {
			expect(replicaUnsafeReason(m), m.name).toBeUndefined();
		}
		handleRef = await boot(config);
		expect(handleRef).toBeDefined();
	});
});

describe('#456: federationTokenStore.type = "redis" in the standalone', () => {
	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	it("reaches the resolved config from FEDERATION_TOKEN_STORE_TYPE", () => {
		// `AppConfigSchema` strips top-level keys it does not declare; the
		// switch had to be declared before an env var could select anything.
		expect(resolveConfig(ALL_REDIS_ENV).federationTokenStore?.type).toBe("redis");
		expect(
			resolveConfig(without(ALL_REDIS_ENV, "FEDERATION_TOKEN_STORE_TYPE")).federationTokenStore
				?.type,
		).toBe("memory");
	});

	it("selects the Redis module and the shared clients module, not the memory one", () => {
		const modules = modulesFor(resolveConfig(ALL_REDIS_ENV));
		const names = modules.map((m) => m.name);
		expect(names).toContain("redis-federation-token-store");
		expect(names).toContain("standalone:redis-clients");
		expect(names).not.toContain("standalone:in-memory-federation-token-store");
		// Exactly one provider for the slot: both modules provide it, so
		// selecting both would be a boot-time slot collision.
		const providers = modules.filter((m) =>
			Object.keys(m.provides ?? {}).includes("federationTokenStore"),
		);
		expect(providers.map((m) => m.name)).toEqual(["redis-federation-token-store"]);
	});

	it("pulls the shared clients module in for the federation store alone", () => {
		// Every other store on memory, single replica: the Redis federation
		// store still needs `federationTokenStoreClient`, which only the shared
		// clients module provides. Without this the branch fails stage 1 with
		// `missing-required-component` — the #439 shape, once more.
		const config = resolveConfig({
			...ALL_REDIS_ENV,
			DEPLOYMENT_MODE: "single",
			USER_SESSION_STORES_ADAPTER: "memory",
			OAUTH_CODE_ADAPTER: "memory",
			RATE_LIMITER_ADAPTER: "memory",
			ACCESS_TOKEN_DENYLIST_ADAPTER: "memory",
		});
		const names = modulesFor(config).map((m) => m.name);
		expect(names).toContain("redis-federation-token-store");
		expect(names).toContain("standalone:redis-clients");
	});

	it("boots, and the resolved store is the Redis adapter", async () => {
		handleRef = await boot(resolveConfig(ALL_REDIS_ENV));
		const store = handleRef.components.federationTokenStore;
		expect(store?.kind).toBe("redis");
	});

	it("fails at boot, naming the key, when the encryption key is missing", async () => {
		// The store encrypts long-lived IdP refresh tokens at rest; a Redis
		// branch with no key is a misconfiguration to refuse at boot, not a
		// store that works until the first federation login.
		const config = resolveConfig(
			without(ALL_REDIS_ENV, "REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY"),
		);
		await expect(boot(config)).rejects.toSatisfy((err: unknown) => {
			const e = err as { message?: string; cause?: { message?: string } };
			return /encryption\.key/.test(`${e.message ?? ""} ${e.cause?.message ?? ""}`);
		});
	});

	it("keeps the memory branch as it was: the default, in single mode, resolves the memory adapter", async () => {
		const config = resolveConfig({
			...without(ALL_REDIS_ENV, "FEDERATION_TOKEN_STORE_TYPE"),
			DEPLOYMENT_MODE: "single",
		});
		const names = modulesFor(config).map((m) => m.name);
		expect(names).toContain("standalone:in-memory-federation-token-store");
		expect(names).not.toContain("redis-federation-token-store");
		handleRef = await boot(config);
		expect(handleRef.components.federationTokenStore?.kind).toBe("memory");
	});
});
