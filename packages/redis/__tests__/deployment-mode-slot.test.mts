/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The two stores that seal upstream refresh tokens read the replica count
 * from core's `deploymentMode` slot, which core fills from the
 * configuration's `core.deployment.mode`. Each module requires the slot, refuses a
 * value that is none of its three, and reads nothing of `deployment` itself.
 * Through `createApp` each refuses plaintext under `multi`, and allows it with
 * the warning under `single`, an empty section and none.
 */

import {
	createApp,
	type DeploymentMode,
	defineModule,
	type Logger,
	type Module,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FederationGrantStoreClient, FederationTokenStoreClient } from "#/clients.mjs";
import {
	redisFederationGrantStoreModule,
	resolveRedisFederationGrantStoreOptions,
} from "#/federation-grant-store.mjs";
import {
	createRedisFederationTokenStore,
	redisFederationTokenStoreBuilder,
	redisFederationTokenStoreModule,
} from "#/federation-tokens.mjs";
import { capturing, withSection } from "./support/section.mjs";

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
} as unknown as FederationTokenStoreClient;

const grantClient = {} as FederationGrantStoreClient;

const refusedUnderMulti = (label: string) =>
	`[${label}] mode "allow-plaintext" is refused because core.deployment.mode is "multi" ` +
	"(a multi-replica deployment is never a development box). " +
	'Set mode to "required" and provide a 32-byte encryption key, OR set ' +
	"FEDERATION_TOKENS_ALLOW_INSECURE=1 to override (NOT recommended for production).";

/** The two modules, each with its plaintext section, its client slot, and the slot it fills. */
const STORES = [
	{
		label: "federation-tokens",
		module: redisFederationTokenStoreModule,
		client: { federationTokenStoreClient: tokenClient },
		plaintext: { "redis-federation-token-store": { encryptionMode: "allow-plaintext" } },
		provided: "federationTokenStore",
	},
	{
		label: "federation-grants",
		module: redisFederationGrantStoreModule,
		client: { federationGrantStoreClient: grantClient },
		plaintext: { "redis-federation-grant-store": { encryptionMode: "allow-plaintext" } },
		provided: "federationGrantStore",
	},
] as const;

/** What becomes of plaintext under every `deployment` core's schema accepts. */
const ACCEPTED = [
	["refused", "core.deployment.mode = multi", { mode: "multi" }],
	["allowed with the warning", "core.deployment.mode = single", { mode: "single" }],
	["allowed with the warning", "an empty deployment section", {}],
	["allowed with the warning", "no deployment section", undefined],
] as const;

const recordingLogger = () => {
	const warn = vi.fn();
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn,
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => logger,
	};
	return { logger: logger as unknown as Logger, warn };
};

/** Stands in for the routes that read a store, so that the store is in the closure boot builds. */
const readerOf = (key: "federationTokenStore" | "federationGrantStore") =>
	defineModule({
		name: `test:${key}-reader`,
		optional: [key] as const,
		contributes: {
			routes: [
				{
					mountPath: `/__test_${key}__`,
					id: `test-${key}`,
					handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
				},
			],
		},
	});

/** The module's provider, run by hand on the deps given. */
const provide = (module: Module, key: string, deps: Record<string, unknown>) =>
	(module.provides as Record<string, (deps: unknown) => unknown>)[key]?.(withSection(module, deps));

let insecure: string | undefined;
let nodeEnv: string | undefined;

beforeEach(() => {
	insecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
	nodeEnv = process.env.NODE_ENV;
	delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
	process.env.NODE_ENV = "development";
});

afterEach(() => {
	if (insecure === undefined) delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
	else process.env.FEDERATION_TOKENS_ALLOW_INSECURE = insecure;
	if (nodeEnv === undefined) delete process.env.NODE_ENV;
	else process.env.NODE_ENV = nodeEnv;
});

describe.each(STORES)("the $label store's module reads the deploymentMode slot", (store) => {
	it("requires the slot", () => {
		expect(store.module.requires).toContain("deploymentMode");
	});

	it("refuses a slot it cannot read, absent included, as a TypeError naming it", () => {
		const { logger } = recordingLogger();
		for (const deploymentMode of [undefined, "MULTI", null, 1]) {
			expect(
				() =>
					provide(store.module, store.provided, {
						...store.client,
						config: { ...store.plaintext, core: { deployment: { mode: "multi" } } },
						...(deploymentMode === undefined ? {} : { deploymentMode }),
						logger,
					}),
				String(deploymentMode),
			).toThrow(TypeError);
		}
	});

	it("refuses plaintext when the slot says multi, whatever the configuration's deployment says", () => {
		const { logger } = recordingLogger();
		expect(() =>
			provide(store.module, store.provided, {
				...store.client,
				config: { ...store.plaintext, core: { deployment: { mode: "single" } } },
				deploymentMode: "multi",
				logger,
			}),
		).toThrow(new RangeError(refusedUnderMulti(store.label)));
	});

	it.each(["single", "unset"] as const)(
		"allows plaintext with the warning when the slot says %s, whatever the configuration's deployment says",
		(deploymentMode: DeploymentMode) => {
			const { logger, warn } = recordingLogger();
			const built = provide(store.module, store.provided, {
				...store.client,
				config: { ...store.plaintext, core: { deployment: { mode: "multi" } } },
				deploymentMode,
				logger,
			}) as { kind: string };
			expect(built.kind).toBe("redis");
			expect(warn).toHaveBeenCalledWith(
				{ store: store.label, mode: "allow-plaintext" },
				"federation_store_plaintext",
			);
		},
	);

	it.each(ACCEPTED)(
		"through createApp, plaintext is %s under %s",
		async (outcome, _what, deployment) => {
			const { logger, warn } = recordingLogger();
			const boot = createApp({
				modules: [store.module, readerOf(store.provided)],
				bootstrapComponents: {
					config: capturing(
						{
							...makeValidCoreConfig(),
							...store.plaintext,
							...(deployment === undefined ? {} : { core: { deployment } }),
						},
						[store.module],
					),
					pathResolver: (p: string) => p,
					logger,
					...store.client,
				} as never,
			});
			if (outcome === "refused") {
				const err = (await boot.catch((thrown: unknown) => thrown)) as Error & {
					reason?: string;
				};
				expect(err.reason).toBe("provides-factory-failed");
				expect(err.cause).toStrictEqual(new RangeError(refusedUnderMulti(store.label)));
				return;
			}
			const handle = await boot;
			try {
				expect((handle.components[store.provided] as { kind: string }).kind).toBe("redis");
				expect(warn).toHaveBeenCalledWith(
					{ store: store.label, mode: "allow-plaintext" },
					"federation_store_plaintext",
				);
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("the grant store's configuration", () => {
	const KEY = Buffer.alloc(32, 7).toString("base64");
	const grants = { encryptionKeys: [{ id: "k", key: KEY }] };

	it("holds no deployment mode in its section: the mode is the slot's", () => {
		expect(
			redisFederationGrantStoreModule.section?.schema.safeParse({
				...grants,
				deployment: { mode: "multi" },
			}).success,
		).toBe(false);
	});

	it("refuses a deployment mode it cannot read — none, MULTI, null, 1 — as a TypeError naming the argument, never building a guard without it", () => {
		const refusal = new TypeError(
			'resolveRedisFederationGrantStoreOptions: deploymentMode must be "single", "multi" or "unset"',
		);
		const plaintextUnderMulti = { encryptionMode: "allow-plaintext" };
		const resolve = resolveRedisFederationGrantStoreOptions as (...args: unknown[]) => unknown;
		expect(() => resolve(plaintextUnderMulti, {})).toThrow(refusal);
		for (const deploymentMode of ["MULTI", null, 1]) {
			expect(
				() => resolve(plaintextUnderMulti, {}, deploymentMode),
				String(deploymentMode),
			).toThrow(refusal);
		}
	});

	it("hands the plaintext guard the mode it is given, not the configuration's", () => {
		expect(resolveRedisFederationGrantStoreOptions(grants, {}, "single").guard).toEqual({
			deploymentMode: "single",
		});
		expect(resolveRedisFederationGrantStoreOptions(grants, {}, "multi").guard).toEqual({
			deploymentMode: "multi",
		});
		expect(
			resolveRedisFederationGrantStoreOptions(grants, { environment: "staging" }, "unset").guard,
		).toEqual({ environment: "staging", deploymentMode: "unset" });
	});
});

describe("the token store's factory and builder hold the deployment mode they are handed", () => {
	const KEY = Buffer.alloc(32, 7);

	/** The two exports a composition root that builds the token store by hand calls. */
	const ENTRIES = [
		{
			name: "createRedisFederationTokenStore",
			build: (options: Record<string, unknown>, logger?: Logger) =>
				createRedisFederationTokenStore({
					client: tokenClient,
					...(logger === undefined ? {} : { logger }),
					...options,
				} as never),
		},
		{
			name: "redisFederationTokenStoreBuilder",
			build: (options: Record<string, unknown>, logger?: Logger) =>
				redisFederationTokenStoreBuilder(
					{ client: tokenClient, ...options },
					logger === undefined ? {} : { logger },
				),
		},
	] as const;

	describe.each(ENTRIES)("$name", (entry) => {
		it("refuses a mode it cannot read — none, MULTI, null, 1 — as a TypeError naming it, before anything is built", () => {
			const refusal = new TypeError(
				`${entry.name}: deploymentMode must be "single", "multi" or "unset"`,
			);
			for (const encryption of [{ mode: "allow-plaintext" }, { mode: "required", key: KEY }]) {
				expect(() => entry.build({ encryption }), `none, ${encryption.mode}`).toThrow(refusal);
				for (const deploymentMode of ["MULTI", null, 1]) {
					expect(
						() => entry.build({ encryption, deploymentMode }),
						`${String(deploymentMode)}, ${encryption.mode}`,
					).toThrow(refusal);
				}
			}
		});

		it("refuses plaintext under multi", () => {
			expect(() =>
				entry.build({ encryption: { mode: "allow-plaintext" }, deploymentMode: "multi" }),
			).toThrow(new RangeError(refusedUnderMulti("federation-tokens")));
		});

		it.each(["single", "unset"] as const)(
			"allows plaintext with the warning under %s",
			(deploymentMode) => {
				const { logger, warn } = recordingLogger();
				const store = entry.build(
					{ encryption: { mode: "allow-plaintext" }, deploymentMode },
					logger,
				) as { kind: string };
				expect(store.kind).toBe("redis");
				expect(warn).toHaveBeenCalledWith(
					{ store: "federation-tokens", mode: "allow-plaintext" },
					"federation_store_plaintext",
				);
			},
		);
	});
});
