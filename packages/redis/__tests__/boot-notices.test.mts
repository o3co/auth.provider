/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The notices this package writes while a composition is built: the plaintext
 * guard's, on the two stores that hold upstream refresh tokens, and the
 * deprecated code-repository builder's. Each is one object-first line with an
 * event name, on the logger the composition hands the module (or builder, or
 * store); `consoleLogger` writes the same line when none is handed over.
 *
 * A line that opens with a string is a message, not a structured event: pino
 * treats what follows as printf arguments, and a query on the event name
 * finds nothing.
 */

import type { Logger } from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
	CodeRepositoryClient,
	FederationGrantStoreClient,
	FederationTokenStoreClient,
} from "#/clients.mjs";
import { redisCodeRepositoryBuilder } from "#/code-repository.mjs";
import {
	createRedisFederationGrantStore,
	redisFederationGrantStoreModuleFor,
} from "#/federation-grant-store.mjs";
import {
	createRedisFederationTokenStore,
	redisFederationTokenStoreBuilder,
	redisFederationTokenStoreModuleFor,
} from "#/federation-tokens.mjs";
import { withSection } from "./support/section.mjs";

/** A logger that records what each level is handed. */
function recordingLogger(): { logger: Logger; calls: Array<{ level: string; args: unknown[] }> } {
	const calls: Array<{ level: string; args: unknown[] }> = [];
	const record =
		(level: string) =>
		(...args: unknown[]): void => {
			calls.push({ level, args });
		};
	const logger: Logger = {
		trace: record("trace"),
		debug: record("debug"),
		info: record("info"),
		warn: record("warn"),
		error: record("error"),
		fatal: record("fatal"),
		child: () => logger,
	};
	return { logger, calls };
}

const tokenClient = {
	get: async () => null,
	set: async () => "OK",
	del: async () => 0,
	unlink: async () => 0,
	sAddWithTtl: async () => {},
	sRem: async () => 0,
	sScanIterator: async function* () {},
	scanIterator: async function* () {},
	compareAndDelete: async () => false,
	readVersioned: async () => null,
	attachRecord: async () => "attached" as const,
	replaceIfGeneration: async () => "missing" as const,
	removeIfGeneration: async () => "missing" as const,
	pExpireGT: async () => {},
	durability: async () => ({
		maxmemoryPolicy: "noeviction",
		appendOnly: true,
		snapshots: undefined,
		refusal: undefined,
	}),
} as unknown as FederationTokenStoreClient;

const grantClient = {} as FederationGrantStoreClient;

const PLAINTEXT = { mode: "allow-plaintext" } as const;

const TOKEN_STORE_CONFIG = {
	"redis-federation-token-store": {
		keyPrefix: "ft:",
		ttl: 86400,
		encryptionMode: "allow-plaintext",
		scanFallback: true,
	},
};

/** The dev-environment line: plaintext is allowed here, and said so. */
const plaintextWarning = (store: string) => ({
	level: "warn",
	args: [{ store, mode: "allow-plaintext" }, "federation_store_plaintext"],
});

describe("the plaintext guard's notices", () => {
	let origEnv: string | undefined;
	let origInsecure: string | undefined;

	beforeEach(() => {
		origEnv = process.env.NODE_ENV;
		origInsecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		process.env.NODE_ENV = "development";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
	});

	afterEach(() => {
		if (origEnv === undefined) delete process.env.NODE_ENV;
		else process.env.NODE_ENV = origEnv;
		if (origInsecure === undefined) delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		else process.env.FEDERATION_TOKENS_ALLOW_INSECURE = origInsecure;
		vi.restoreAllMocks();
	});

	it("warns once, object-first, where plaintext is allowed", async () => {
		const { logger, calls } = recordingLogger();
		await createRedisFederationTokenStore({
			client: tokenClient,
			encryption: PLAINTEXT,
			environment: "development",
			deploymentMode: "single",
			logger,
		});
		expect(calls).toEqual([plaintextWarning("federation-tokens")]);
	});

	it("logs once at error, naming what refused it, when the override lets plaintext through", async () => {
		process.env.FEDERATION_TOKENS_ALLOW_INSECURE = "1";
		const { logger, calls } = recordingLogger();
		await createRedisFederationTokenStore({
			client: tokenClient,
			encryption: PLAINTEXT,
			environment: "production",
			deploymentMode: "multi",
			logger,
		});
		expect(calls).toEqual([
			{
				level: "error",
				args: [
					{
						store: "federation-tokens",
						mode: "allow-plaintext",
						environment: "production",
						deploymentMode: "multi",
						override: "FEDERATION_TOKENS_ALLOW_INSECURE",
					},
					"federation_store_plaintext_override",
				],
			},
		]);
	});

	it("the grant store writes the same lines under its own name", () => {
		const warned = recordingLogger();
		createRedisFederationGrantStore({
			client: grantClient,
			encryption: PLAINTEXT,
			guard: { logger: warned.logger },
		});
		expect(warned.calls).toEqual([plaintextWarning("federation-grants")]);

		process.env.FEDERATION_TOKENS_ALLOW_INSECURE = "1";
		const overridden = recordingLogger();
		createRedisFederationGrantStore({
			client: grantClient,
			encryption: PLAINTEXT,
			guard: { deploymentMode: "multi", logger: overridden.logger },
		});
		expect(overridden.calls).toEqual([
			{
				level: "error",
				args: [
					{
						store: "federation-grants",
						mode: "allow-plaintext",
						deploymentMode: "multi",
						override: "FEDERATION_TOKENS_ALLOW_INSECURE",
					},
					"federation_store_plaintext_override",
				],
			},
		]);
	});

	it("the token store's builder writes its context's logger, once", async () => {
		const { logger, calls } = recordingLogger();
		await redisFederationTokenStoreBuilder(
			{ deploymentMode: "unset", client: tokenClient, encryption: PLAINTEXT },
			{ logger },
		);
		expect(calls).toEqual([plaintextWarning("federation-tokens")]);
	});

	it("each module writes the composition's logger slot, once", async () => {
		const tokens = recordingLogger();
		const tokenModule = redisFederationTokenStoreModuleFor();
		const provideTokens = tokenModule.provides?.federationTokenStore as (deps: unknown) => unknown;
		await provideTokens(
			withSection(tokenModule, {
				federationTokenStoreClient: tokenClient,
				config: TOKEN_STORE_CONFIG,
				deploymentMode: "unset",
				logger: tokens.logger,
			}),
		);
		expect(tokens.calls).toEqual([plaintextWarning("federation-tokens")]);

		const grants = recordingLogger();
		const grantModule = redisFederationGrantStoreModuleFor();
		const provideGrants = grantModule.provides?.federationGrantStore as (deps: unknown) => unknown;
		provideGrants(
			withSection(grantModule, {
				federationGrantStoreClient: grantClient,
				config: { "redis-federation-grant-store": { encryptionMode: "allow-plaintext" } },
				deploymentMode: "unset",
				logger: grants.logger,
			}),
		);
		expect(grants.calls).toEqual([plaintextWarning("federation-grants")]);
	});

	it("with no logger handed over, consoleLogger writes the same one line", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		await createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: tokenClient,
			encryption: PLAINTEXT,
		});
		expect(warn.mock.calls).toEqual([
			[{ store: "federation-tokens", mode: "allow-plaintext" }, "federation_store_plaintext"],
		]);
		expect(error).not.toHaveBeenCalled();
	});
});

describe("the token store module's eviction gate, which writes no notice", () => {
	const SEALED_CONFIG = {
		"redis-federation-token-store": {
			encryptionKey: Buffer.alloc(32, 7).toString("base64"),
		},
	};

	/** Provides the store through the module, its client's server answering `durability`. */
	const provideOver = async (durability: FederationTokenStoreClient["durability"]) => {
		const { logger, calls } = recordingLogger();
		const module = redisFederationTokenStoreModuleFor();
		const provide = module.provides?.federationTokenStore as (deps: unknown) => unknown;
		const store = (await provide(
			withSection(module, {
				federationTokenStoreClient: { ...tokenClient, durability },
				config: SEALED_CONFIG,
				deploymentMode: "multi",
				logger,
			}),
		)) as { kind: string };
		return { store, calls };
	};

	const report = (maxmemoryPolicy: string | undefined, refusal?: unknown) => async () => ({
		maxmemoryPolicy,
		appendOnly: true,
		snapshots: undefined,
		refusal,
	});

	it("says nothing on a noeviction server", async () => {
		const { store, calls } = await provideOver(report("noeviction"));
		expect(store.kind).toBe("redis");
		expect(calls).toEqual([]);
	});

	it.each([
		"volatile-lru",
		"volatile-lfu",
		"volatile-random",
		"volatile-ttl",
		"allkeys-lru",
		"allkeys-lfu",
		"allkeys-random",
	])(
		"refuses the boot on a server whose policy is %s, naming the policy and the fix",
		async (policy) => {
			const refused = provideOver(report(policy));
			await expect(refused).rejects.toMatchObject({
				name: "RedisStoreEvictableError",
				reason: "federation-token-store-evictable",
				maxmemoryPolicy: policy,
			});
			await expect(refused).rejects.toThrow(
				new RegExp(
					`federationTokenStore: the Redis server's maxmemory-policy is "${policy}".*set maxmemory-policy to "noeviction", or give federationTokenStore a server of its own`,
				),
			);
		},
	);

	it("refuses, writing no line, a policy it does not know, one it cannot read and a server that cannot answer", async () => {
		const refusal = Object.assign(new Error("ERR unknown command 'CONFIG'"), {
			name: "ReplyError",
		});
		const outage = new Error("connect ECONNREFUSED");
		for (const [durability, rejection] of [
			[report("some-future-policy"), { reason: "federation-token-store-evictable" }],
			[report(undefined, refusal), { reason: "federation-token-store-evictable" }],
			[
				async () => {
					throw outage;
				},
				outage,
			],
		] as const) {
			const { logger, calls } = recordingLogger();
			const module = redisFederationTokenStoreModuleFor();
			const provide = module.provides?.federationTokenStore as (deps: unknown) => unknown;
			await expect(
				provide(
					withSection(module, {
						federationTokenStoreClient: { ...tokenClient, durability },
						config: SEALED_CONFIG,
						deploymentMode: "multi",
						logger,
					}),
				),
			).rejects.toMatchObject(rejection);
			expect(calls).toEqual([]);
		}
	});

	it("boots, writing no line, on a policy it cannot read when the client assumes noeviction", async () => {
		const { store, calls } = await provideOver(async () => ({
			...(await report(undefined)()),
			assumeNoEviction: true,
		}));
		expect(store.kind).toBe("redis");
		expect(calls).toEqual([]);
	});
});

describe("redisCodeRepositoryBuilder's deprecation notice", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	const client = {} as CodeRepositoryClient;

	it("is one object-first warn on the builder context's logger", () => {
		const { logger, calls } = recordingLogger();
		redisCodeRepositoryBuilder({ client }, { logger });
		expect(calls).toEqual([
			{
				level: "warn",
				args: [
					{ builder: "redisCodeRepositoryBuilder", replacement: "redisCodeRepositoryModule" },
					"adapter_builder_deprecated",
				],
			},
		]);
	});

	it("goes to consoleLogger when the context has none, still one object-first line", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		redisCodeRepositoryBuilder({ client }, {});
		expect(warn.mock.calls).toEqual([
			[
				{ builder: "redisCodeRepositoryBuilder", replacement: "redisCodeRepositoryModule" },
				"adapter_builder_deprecated",
			],
		]);
	});
});
