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
 * The standalone's own store modules under `core.deployment.mode = "multi"`,
 * booted the way an operator reaches them: from the shipped HOCON with one
 * environment variable flipped.
 *
 * - Every memory branch must be refused by name, and the all-Redis
 *   environment must boot. The replica-safety guard reads each module's
 *   manifest declaration, which covers the template's own in-memory modules
 *   and express-session's store (`sessionStoreModule`, which declares from
 *   its own section).
 * - `federationTokenStore.type = "redis"` mounts
 *   `redisFederationTokenStoreModule` off the shared ioredis socket.
 * - The Redis federation store's `allow-plaintext` guard reads the
 *   environment the config was selected by (`CONFIG_ENV || NODE_ENV`, passed
 *   through `buildModules`) and refuses under `core.deployment.mode = "multi"` in
 *   every environment.
 *
 * ioredis, node-redis and connect-redis are mocked, as in
 * `device-code-store-client-module.test.mts`: the point is composition and
 * the boot planner's stage-1 verdict, not Redis. Nothing here issues a
 * command.
 */

import { fileURLToPath } from "node:url";
import {
	AppConfigSchema,
	createApp,
	createKeyStoreFactory,
	defineModule,
	InMemoryClientRepository,
	InMemoryUserRepository,
	type Module,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
	replicaUnsafeReason,
} from "@o3co/auth-provider-core";
import { sessionStoreModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import { standardSmtpMailSenderConfigForTests } from "@o3co/auth-provider-standard/testing";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, type Switches } from "../configPath.mjs";
import { templateReference } from "../modules.mjs";
import {
	capturedRenames,
	libraryLayers,
	rootSectionsOf,
	sectionsCoreDoesNotDeclare,
} from "./library-references.fixture.mjs";

// The redis session-store builder, which the baseline selects, dynamically
// imports these; mock them so no socket opens.
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
	// express-session subscribes to store events, so the fake must be an
	// EventEmitter rather than a plain object.
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
 * every shared store on Redis, express-session's own included, and MFA off
 * as the umbrella sets it. Each case below flips one variable off this.
 */
const ALL_REDIS_ENV: Readonly<Record<string, string>> = {
	MFA_MODE: "off",
	KEY_STORE_LOCAL_ALGORITHM: "HS256",
	KEY_STORE_LOCAL_SECRET: "replica-safety-test-secret.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_STORE_SECRET: "replica-safety-session-secret.at-least-32-bytes.ok",
	SESSION_STORE_SECURE: "false",
	SESSION_STORE_NAME: "auth.session",
	SESSION_STORE_STORAGE_TYPE: "redis",
	SESSION_STORE_STORAGE_REDIS_URL: "redis://redis.test:6379",
	ADAPTERS_USER_REPOSITORY: "yaml",
	CORE_DEPLOYMENT_MODE: "multi",
	REDIS_CLIENTS_URL: "redis://redis.test:6379",
	ADAPTERS_USER_SESSION_STORES: "redis",
	ADAPTERS_RATE_LIMITER: "redis",
	// The login's attempt counter, shared: per process, `multi` refuses the login.
	ADAPTERS_ATTEMPT_COUNTER: "redis",
	ADAPTERS_CODE_REPOSITORY: "redis",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "redis",
	ADAPTERS_REPLAY_SEEN_SET: "redis",
	ADAPTERS_FEDERATION_TOKEN_STORE: "redis",
	REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY: ENCRYPTION_KEY,
	// The consent step for clients that are not first-party, on the
	// shared store — the one switch value `multi` accepts besides `none`.
	ADAPTERS_CONSENT_STORE: "redis",
};

function resolveConfig(env: Record<string, string>): Switches {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	const layers = parseFile(envConfPath, { env })
		.withFallback(parseFile(applicationConfPath, { env }))
		.withFallback(parseFile(fileURLToPath(templateReference()), { env }))
		.withFallback(libraryLayers(env));
	return {
		...sectionsCoreDoesNotDeclare(layers),
		...rootSectionsOf(layers, env),
		...validate(layers, AppConfigSchema),
		// What the resolution captured of core's renamed variables, which the
		// schema's parse drops.
		"renamed-variables": capturedRenames(env),
	} as Switches;
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
				...((c as { "key-store"?: { local?: object } })["key-store"]?.local ?? {}),
			});
		},
	},
});

const modulesFor = (config: Switches, environment?: string) =>
	buildModules(config, {
		keyStoreModule: testKeyStoreModule,
		repositoriesModule: testRepositoriesModule,
		...(environment === undefined ? {} : { environment }),
	});

/**
 * `module`'s section in `config`, for a declaration made from it: each module
 * here that has one sits at its name.
 */
const sectionOf = (config: Switches, module: Module): unknown =>
	(config as unknown as Record<string, unknown>)[module.name];

const boot = (config: Switches, environment?: string) =>
	createApp({
		modules: modulesFor(config, environment),
		bootstrapComponents: { config, pathResolver: (s) => s },
	});

/** The message of a boot failure and of the module error it wraps, together. */
const messageChain = (err: unknown): string => {
	const e = err as { message?: string; cause?: { message?: string } };
	return `${e.message ?? ""} ${e.cause?.message ?? ""}`;
};

describe('the standalone\'s memory modules are refused under core.deployment.mode = "multi"', () => {
	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	const cases: ReadonlyArray<readonly [variable: string, module: string]> = [
		// The template's own modules.
		["ADAPTERS_USER_SESSION_STORES", "standalone-in-memory-session-stores"],
		["ADAPTERS_CODE_REPOSITORY", "standalone-in-memory-code-repository"],
		["ADAPTERS_FEDERATION_TOKEN_STORE", "standalone-in-memory-federation-token-store"],
		// express-session's own store. Not a module of this template: it
		// declares from its own section, which boot parses.
		["SESSION_STORE_STORAGE_TYPE", "session-store"],
		// The consent store, wired only when the switch says so.
		["ADAPTERS_CONSENT_STORE", "core-consent-store-memory"],
		// Core's, selected by the same kind of switch.
		["ADAPTERS_RATE_LIMITER", "core-rate-limiter-memory"],
		["ADAPTERS_ACCESS_TOKEN_DENYLIST", "core-access-token-denylist-memory"],
		// The jti single-use record behind private_key_jwt client auth.
		["ADAPTERS_REPLAY_SEEN_SET", "core-replay-seen-set-memory"],
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
			ADAPTERS_USER_SESSION_STORES: "memory",
			ADAPTERS_CODE_REPOSITORY: "memory",
			ADAPTERS_FEDERATION_TOKEN_STORE: "memory",
			SESSION_STORE_STORAGE_TYPE: "memory",
			ADAPTERS_RATE_LIMITER: "memory",
			ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
			ADAPTERS_REPLAY_SEEN_SET: "memory",
			ADAPTERS_CONSENT_STORE: "memory",
		});
		await expect(boot(config)).rejects.toMatchObject({
			reason: "replica-unsafe-adapter",
			details: {
				modules: expect.arrayContaining(cases.map(([, module]) => module)),
			},
		});
	});

	it("each standalone memory module declares its consequence on its own manifest", () => {
		// The declaration is what the guard reads, so it has to be on
		// the module and it has to say what breaks — the guard quotes it.
		const config = resolveConfig({
			...ALL_REDIS_ENV,
			ADAPTERS_USER_SESSION_STORES: "memory",
			ADAPTERS_CODE_REPOSITORY: "memory",
			ADAPTERS_FEDERATION_TOKEN_STORE: "memory",
		});
		const standaloneMemoryModules = modulesFor(config).filter((m) =>
			m.name.startsWith("standalone-in-memory-"),
		);
		expect(standaloneMemoryModules.map((m) => m.name).sort()).toEqual([
			"standalone-in-memory-code-repository",
			"standalone-in-memory-federation-token-store",
			"standalone-in-memory-session-stores",
		]);
		for (const m of standaloneMemoryModules) {
			expect(replicaUnsafeReason(m), m.name).toBeDefined();
			expect((replicaUnsafeReason(m) ?? "").length, m.name).toBeGreaterThan(40);
		}
	});

	it("boots the all-Redis environment, with nothing declaring replica-unsafe state", async () => {
		const config = resolveConfig(ALL_REDIS_ENV);
		for (const m of modulesFor(config)) {
			expect(replicaUnsafeReason(m, sectionOf(config, m)), m.name).toBeUndefined();
		}
		handleRef = await boot(config);
		expect(handleRef).toBeDefined();
	});
});

describe("express-session's store declares its replica safety from its own section", () => {
	it("is the session package's sessionStoreModule, listed first", () => {
		expect(modulesFor(resolveConfig(ALL_REDIS_ENV))[0]).toBe(sessionStoreModule);
	});

	/** Each way the storage type is set, laid over the all-Redis environment. */
	const STORAGE: ReadonlyArray<readonly [string, Record<string, string>]> = [
		[
			"SESSION_STORE_STORAGE_TYPE=memory",
			{ ...ALL_REDIS_ENV, SESSION_STORE_STORAGE_TYPE: "memory" },
		],
		["SESSION_STORE_STORAGE_TYPE=redis", ALL_REDIS_ENV],
		[
			"no SESSION_STORE_STORAGE_TYPE, the reference's default",
			without(ALL_REDIS_ENV, "SESSION_STORE_STORAGE_TYPE"),
		],
		[
			"the variable it was renamed from, SESSION_STORAGE_TYPE=memory",
			{ ...without(ALL_REDIS_ENV, "SESSION_STORE_STORAGE_TYPE"), SESSION_STORAGE_TYPE: "memory" },
		],
	];
	const MODES: ReadonlyArray<
		readonly [string, (env: Record<string, string>) => Record<string, string>]
	> = [
		["multi", (env) => ({ ...env, CORE_DEPLOYMENT_MODE: "multi" })],
		["single", (env) => ({ ...env, CORE_DEPLOYMENT_MODE: "single" })],
		["unset", (env) => without(env, "CORE_DEPLOYMENT_MODE")],
	];

	/** What a boot of `modules` settles as: the refusal, or the replica-safety warnings it logged. */
	async function outcomeOf(config: Switches, modules: readonly Module[]): Promise<unknown> {
		const warn = vi.fn();
		const logger = {
			warn,
			info: vi.fn(),
			error: vi.fn(),
			debug: vi.fn(),
			trace: vi.fn(),
			fatal: vi.fn(),
			child: vi.fn(),
		};
		try {
			const handle = await createApp({
				modules: [...modules],
				bootstrapComponents: { config, logger, pathResolver: (s: string) => s } as never,
			});
			await handle.dispose();
		} catch (err) {
			const e = err as { reason?: string; message?: string; details?: unknown };
			return { refused: { reason: e.reason, message: e.message, details: e.details } };
		}
		return {
			warned: warn.mock.calls.filter(([, event]) => event === "replica_unsafe_adapters"),
		};
	}

	for (const [storage, env] of STORAGE) {
		for (const [mode, withMode] of MODES) {
			it(`${storage} under ${mode} settles as sessionStoreModuleFor(config) does`, async () => {
				const config = resolveConfig(withMode(env));
				const modules = modulesFor(config);
				expect(modules[0]).toBe(sessionStoreModule);
				const outcome = await outcomeOf(config, modules);
				expect(outcome).toEqual(
					await outcomeOf(config, [sessionStoreModuleFor(config), ...modules.slice(1)]),
				);
				if (storage === "SESSION_STORE_STORAGE_TYPE=memory") {
					const named = { modules: ["session-store"] };
					expect(outcome).toEqual(
						mode === "multi"
							? {
									refused: expect.objectContaining({
										reason: "replica-unsafe-adapter",
										message: expect.stringContaining(
											"session-store: the express-session store forks per replica",
										),
										details: expect.objectContaining(named),
									}),
								}
							: {
									warned:
										mode === "unset"
											? [[expect.objectContaining(named), "replica_unsafe_adapters"]]
											: [],
								},
					);
				}
			});
		}
	}
});

describe('adapters.federationTokenStore = "redis" in the standalone', () => {
	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	it("reaches phase one's adapters from ADAPTERS_FEDERATION_TOKEN_STORE", () => {
		expect(resolveConfig(ALL_REDIS_ENV).adapters.federationTokenStore).toBe("redis");
		expect(
			resolveConfig(without(ALL_REDIS_ENV, "ADAPTERS_FEDERATION_TOKEN_STORE")).adapters
				.federationTokenStore,
		).toBe("memory");
	});

	it("selects the Redis module and the shared clients module, not the memory one", () => {
		const modules = modulesFor(resolveConfig(ALL_REDIS_ENV));
		const names = modules.map((m) => m.name);
		expect(names).toContain("redis-federation-token-store");
		expect(names).toContain("redis-clients");
		expect(names).not.toContain("standalone-in-memory-federation-token-store");
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
		// `missing-required-component`.
		const config = resolveConfig({
			...ALL_REDIS_ENV,
			CORE_DEPLOYMENT_MODE: "single",
			ADAPTERS_USER_SESSION_STORES: "memory",
			ADAPTERS_CODE_REPOSITORY: "memory",
			ADAPTERS_RATE_LIMITER: "memory",
			ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
		});
		const names = modulesFor(config).map((m) => m.name);
		expect(names).toContain("redis-federation-token-store");
		expect(names).toContain("redis-clients");
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

	it("keeps the memory branch: the default, in single mode, resolves the memory adapter", async () => {
		const config = resolveConfig({
			...without(ALL_REDIS_ENV, "ADAPTERS_FEDERATION_TOKEN_STORE"),
			CORE_DEPLOYMENT_MODE: "single",
		});
		const names = modulesFor(config).map((m) => m.name);
		expect(names).toContain("standalone-in-memory-federation-token-store");
		expect(names).not.toContain("redis-federation-token-store");
		handleRef = await boot(config);
		expect(handleRef.components.federationTokenStore?.kind).toBe("memory");
	});
});

describe('consentStore.adapter = "redis" in the standalone', () => {
	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	it("selects the Redis consent module, providing both slots, and not the memory one", () => {
		const modules = modulesFor(resolveConfig(ALL_REDIS_ENV));
		const names = modules.map((m) => m.name);
		expect(names).toContain("redis-consent-store");
		expect(names).not.toContain("core-consent-store-memory");
		// Exactly one provider for each slot: the consent step refuses a
		// composition with one and not the other, and two would collide.
		for (const slot of ["consentStore", "pendingConsentStore"]) {
			const providers = modules.filter((m) => Object.keys(m.provides ?? {}).includes(slot));
			expect(
				providers.map((m) => m.name),
				slot,
			).toEqual(["redis-consent-store"]);
		}
	});

	it("pulls the shared clients module in for the consent stores alone", () => {
		// Every other store on memory, single replica: the consent module still
		// needs its two client slots, which only the shared clients module
		// provides.
		const config = resolveConfig({
			...ALL_REDIS_ENV,
			CORE_DEPLOYMENT_MODE: "single",
			ADAPTERS_USER_SESSION_STORES: "memory",
			ADAPTERS_CODE_REPOSITORY: "memory",
			ADAPTERS_RATE_LIMITER: "memory",
			ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
			ADAPTERS_REPLAY_SEEN_SET: "memory",
			ADAPTERS_FEDERATION_TOKEN_STORE: "memory",
		});
		const names = buildModules(config, {
			keyStoreModule: testKeyStoreModule,
			repositoriesModule: testRepositoriesModule,
			refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
		}).map((m) => m.name);
		expect(names).toContain("redis-consent-store");
		expect(names).toContain("redis-clients");
	});

	it("boots under CORE_DEPLOYMENT_MODE=multi with both slots resolved to the Redis adapters", async () => {
		handleRef = await boot(resolveConfig(ALL_REDIS_ENV));
		expect(handleRef.components.consentStore?.kind).toBe("redis");
		expect(handleRef.components.pendingConsentStore?.kind).toBe("redis");
	});
});

describe("the Redis federation store's plaintext guard, booted from the shipped config", () => {
	let handleRef: Awaited<ReturnType<typeof boot>> | undefined;
	let warnSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;
	let origInsecure: string | undefined;

	beforeEach(() => {
		// vitest runs with NODE_ENV=test: not a production name, so every
		// refusal below comes from what the standalone passes, not from NODE_ENV.
		expect(process.env.NODE_ENV).not.toMatch(/^(production|staging)$/);
		origInsecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
	});

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
		if (origInsecure === undefined) delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		else process.env.FEDERATION_TOKENS_ALLOW_INSECURE = origInsecure;
		warnSpy.mockRestore();
		errorSpy.mockRestore();
	});

	/** All-Redis, with the federation store told to skip encryption. */
	const PLAINTEXT_ENV: Readonly<Record<string, string>> = {
		...without(ALL_REDIS_ENV, "REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY"),
		REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_MODE: "allow-plaintext",
	};

	it('is refused under core.deployment.mode = "multi" in an environment that is not production', async () => {
		// The umbrella shape with plaintext. A multi-replica deployment is
		// never a development box. A development configuration under multi is
		// refused by the development mail sender first, so the environment here
		// is another name that is not production, with the SMTP sender's section.
		await expect(
			boot({ ...resolveConfig(PLAINTEXT_ENV), ...standardSmtpMailSenderConfigForTests() }, "test"),
		).rejects.toSatisfy((err: unknown) =>
			/allow-plaintext[\s\S]*core\.deployment\.mode is "multi"/.test(messageChain(err)),
		);
		expect(errorSpy).not.toHaveBeenCalled();
	});

	it("is refused when the config was selected by CONFIG_ENV=production, whatever NODE_ENV says", async () => {
		// `app.mts` selects `production.conf` by `CONFIG_ENV || NODE_ENV` and
		// passes that name through `buildModules`; the guard reads that name,
		// not NODE_ENV alone.
		// Under production the template installs the SMTP sender's module, whose
		// section the package's builder carries.
		const config = {
			...resolveConfig({ ...PLAINTEXT_ENV, CORE_DEPLOYMENT_MODE: "single" }),
			...standardSmtpMailSenderConfigForTests(),
		};
		await expect(boot(config, "production")).rejects.toSatisfy((err: unknown) =>
			/allow-plaintext[\s\S]*the environment is "production"/.test(messageChain(err)),
		);
	});

	it("boots with the plaintext warning in a development environment on a single replica", async () => {
		const config = resolveConfig({ ...PLAINTEXT_ENV, CORE_DEPLOYMENT_MODE: "single" });
		handleRef = await boot(config, "development");
		expect(handleRef.components.federationTokenStore?.kind).toBe("redis");
		expect(warnSpy).toHaveBeenCalledWith(
			{ store: "federation-tokens", mode: "allow-plaintext" },
			"federation_store_plaintext",
		);
	});

	it("keeps the FEDERATION_TOKENS_ALLOW_INSECURE=1 escape hatch under multi, logged at error", async () => {
		process.env.FEDERATION_TOKENS_ALLOW_INSECURE = "1";
		// Under multi the development mail sender refuses a development
		// configuration, so the environment here is another name that is not
		// production, with the SMTP sender's section its module reads.
		handleRef = await boot(
			{ ...resolveConfig(PLAINTEXT_ENV), ...standardSmtpMailSenderConfigForTests() },
			"test",
		);
		expect(errorSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				store: "federation-tokens",
				deploymentMode: "multi",
				override: "FEDERATION_TOKENS_ALLOW_INSECURE",
			}),
			"federation_store_plaintext_override",
		);
	});
});
