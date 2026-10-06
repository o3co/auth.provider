/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import {
	createApp,
	type DeploymentMode,
	defineModule,
	type Module,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FederationTokenStoreClient } from "#/clients.mjs";
import {
	createRedisFederationTokenStore,
	redisFederationTokenStoreBuilder,
	redisFederationTokenStoreModule,
	redisFederationTokenStoreModuleFor,
} from "#/federation-tokens.mjs";
import { withSection } from "./support/section.mjs";

const fakeClient = () => ({
	get: () => null,
	set: () => null,
	del: () => 0,
	unlink: () => 0,
	sAddWithTtl: async () => {},
	sRem: async () => 0,
	sScanIterator: () => [],
	scanIterator: () => [],
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
});

/** Runs a module's `federationTokenStore` provider against a plaintext config, with the mode core fills. */
const provideFrom = (module: Module, deploymentMode: DeploymentMode = "unset") => {
	const provider = module.provides?.federationTokenStore as (deps: unknown) => unknown;
	return provider(
		withSection(module, {
			federationTokenStoreClient: fakeClient(),
			config: {
				"redis-federation-token-store": {
					keyPrefix: "ft:",
					ttl: 86400,
					encryptionMode: "allow-plaintext",
					scanFallback: true,
				},
			},
			deploymentMode,
		}),
	);
};

describe("the module hands the guard the selected environment and the deployment mode", () => {
	let origEnv: string | undefined;
	let warnSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		origEnv = process.env.NODE_ENV;
		process.env.NODE_ENV = "development";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
	});

	afterEach(() => {
		if (origEnv === undefined) delete process.env.NODE_ENV;
		else process.env.NODE_ENV = origEnv;
		warnSpy.mockRestore();
	});

	it("keeps the manifest of the default module: same name, requires and section schema", () => {
		const m = redisFederationTokenStoreModuleFor({ environment: "production" });
		expect(m.name).toBe(redisFederationTokenStoreModule.name);
		expect(m.requires).toEqual(redisFederationTokenStoreModule.requires);
		expect(m.section?.schema).toBe(redisFederationTokenStoreModule.section?.schema);
	});

	it("refuses plaintext when the composition root passes a production environment", async () => {
		await expect(
			provideFrom(redisFederationTokenStoreModuleFor({ environment: "production" })),
		).rejects.toThrow(/the environment is "production"/);
	});

	it('refuses plaintext when the deploymentMode slot is "multi" — default module included', async () => {
		await expect(provideFrom(redisFederationTokenStoreModule, "multi")).rejects.toThrow(
			/core\.deployment\.mode is "multi"/,
		);
		await expect(
			provideFrom(redisFederationTokenStoreModuleFor({ environment: "development" }), "multi"),
		).rejects.toThrow(/core\.deployment\.mode is "multi"/);
	});

	it("warns and builds the store in development with the deployment mode unset or single", async () => {
		const store = (await provideFrom(
			redisFederationTokenStoreModuleFor({ environment: "development" }),
			"single",
		)) as { kind: string };
		expect(store.kind).toBe("redis");
		expect(
			((await provideFrom(redisFederationTokenStoreModuleFor({}))) as { kind: string }).kind,
		).toBe("redis");
		expect(warnSpy).toHaveBeenCalledWith(
			{ store: "federation-tokens", mode: "allow-plaintext" },
			"federation_store_plaintext",
		);
	});
});

describe("redisFederationTokenStoreModule", () => {
	it("has the canonical name", () => {
		expect(redisFederationTokenStoreModule.name).toBe("redis-federation-token-store");
	});

	it("requires federationTokenStoreClient, config and deploymentMode", () => {
		expect(redisFederationTokenStoreModule.requires).toEqual([
			"federationTokenStoreClient",
			"deploymentMode",
		]);
	});

	it("provides federationTokenStore", () => {
		expect(typeof redisFederationTokenStoreModule.provides?.federationTokenStore).toBe("function");
	});

	it("reads its own section, redis-federation-token-store, with its defaults", () => {
		expect(redisFederationTokenStoreModule).not.toHaveProperty("configSchema");
		expect(redisFederationTokenStoreModule.section?.schema.parse(undefined)).toEqual({
			keyPrefix: "ft:",
			ttl: 86400,
			encryptionMode: "required",
			scanFallback: true,
		});
	});
});

describe("redisFederationTokenStoreBuilder", () => {
	it("rejects missing client", async () => {
		await expect(redisFederationTokenStoreBuilder({ deploymentMode: "unset" }, {})).rejects.toThrow(
			/'client' option is required/,
		);
	});

	it("rejects encryption.required without 32-byte key", async () => {
		const fakeClient = {
			get: () => null,
			set: () => null,
			del: () => 0,
			unlink: () => 0,
			sAddWithTtl: async () => {},
			sRem: async () => 0,
			sScanIterator: () => [],
			scanIterator: () => [],
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
		};
		await expect(
			redisFederationTokenStoreBuilder(
				{
					deploymentMode: "unset",
					client: fakeClient,
					encryption: { mode: "required", key: Buffer.alloc(16) },
				},
				{},
			),
		).rejects.toThrow(/32 bytes/);
	});

	it("accepts encryption.allow-plaintext", async () => {
		const fakeClient = {
			get: () => null,
			set: () => null,
			del: () => 0,
			unlink: () => 0,
			sAddWithTtl: async () => {},
			sRem: async () => 0,
			sScanIterator: () => [],
			scanIterator: () => [],
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
		};
		// No throw expected
		const store = (await redisFederationTokenStoreBuilder(
			{
				deploymentMode: "unset",
				client: fakeClient,
				encryption: { mode: "allow-plaintext" },
			},
			{},
		)) as { kind: string };
		expect(store.kind).toBe("redis");
	});
});

/**
 * Stands in for the routes that read the store, so that the store is in the
 * closure boot builds.
 */
const tokensReader = defineModule({
	name: "test:federation-token-store-reader",
	optional: ["federationTokenStore"] as const,
	contributes: {
		routes: [
			{
				mountPath: "/__test_noop__",
				id: "test-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

/**
 * Boots the module through `createApp` over a valid core configuration,
 * requires the boot to fail on the store's provider, naming the module, and
 * answers the BootError's cause.
 */
const bootRefusal = async (extra: Record<string, unknown>): Promise<unknown> => {
	const boot = createApp({
		modules: [redisFederationTokenStoreModule, tokensReader],
		bootstrapComponents: {
			config: { ...makeValidCoreConfig(), ...extra },
			pathResolver: (p: string) => p,
			federationTokenStoreClient: fakeClient(),
		} as never,
	});
	await expect(boot).rejects.toMatchObject({
		name: "BootError",
		reason: "provides-factory-failed",
		details: { module: "redis-federation-token-store", componentKey: "federationTokenStore" },
	});
	return ((await boot.catch((err: unknown) => err)) as Error).cause;
};

const MESSAGE_KEY =
	"federationTokenStore.redis: encryption.key must be canonical base64 of 32 bytes (AES-256), or a Buffer of 32 bytes, when encryption.mode is 'required' (the default)";

const PLAINTEXT_UNDER_MULTI =
	'[federation-tokens] mode "allow-plaintext" is refused because core.deployment.mode is "multi" ' +
	"(a multi-replica deployment is never a development box). " +
	'Set mode to "required" and provide a 32-byte encryption key, OR set ' +
	"FEDERATION_TOKENS_ALLOW_INSECURE=1 to override (NOT recommended for production).";

const KEY_OF_16 = Buffer.alloc(16, 7).toString("base64");
/** 32 bytes of key material, as `openssl rand -base64 32` prints it (without the newline). */
const KEY_OF_32 = Buffer.alloc(32, 0xfb).toString("base64");

describe("every setting the token store is given and cannot use is refused as a RangeError", () => {
	let insecure: string | undefined;

	beforeEach(() => {
		insecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
	});

	afterEach(() => {
		if (insecure !== undefined) process.env.FEDERATION_TOKENS_ALLOW_INSECURE = insecure;
	});

	it("through the factory: a key that is not 32 bytes, plaintext where it is refused, a TTL past the Date range", async () => {
		const client = fakeClient() as unknown as FederationTokenStoreClient;
		await expect(
			createRedisFederationTokenStore({
				deploymentMode: "unset",
				client,
				encryption: { mode: "required", key: Buffer.alloc(16, 7) },
			}),
		).rejects.toThrow(
			new RangeError("FederationTokenStore redis: encryption key must be 32 bytes"),
		);
		// A 32-character string has the length, and would be used as its UTF-8
		// bytes: 32 printable characters, not 32 bytes of key material.
		await expect(
			createRedisFederationTokenStore({
				deploymentMode: "unset",
				client,
				encryption: { mode: "required", key: "k".repeat(32) as unknown as Buffer },
			}),
		).rejects.toThrow(
			new RangeError("FederationTokenStore redis: encryption key must be 32 bytes"),
		);
		await expect(
			createRedisFederationTokenStore({
				client,
				encryption: { mode: "allow-plaintext" },
				deploymentMode: "multi",
			}),
		).rejects.toThrow(new RangeError(PLAINTEXT_UNDER_MULTI));
		await expect(
			createRedisFederationTokenStore({
				deploymentMode: "unset",
				client,
				encryption: { mode: "required", key: Buffer.alloc(32, 7) },
				ttl: 1e20,
			}),
		).rejects.toThrow(RangeError);
	});

	it("through the builder: a configured key that is not canonical base64 of 32 bytes is refused, not tidied up", async () => {
		// `Buffer.from(…, "base64")` reads a key with a trailing newline, in the
		// URL alphabet, or without its padding as the same 32 bytes: a value an
		// operator has to tidy up to read is not the value they checked. Core's
		// `decodeSealingKey` is the one rule for a configured key.
		for (const key of [
			`${KEY_OF_32}\n`,
			` ${KEY_OF_32}`,
			Buffer.alloc(32, 0xfb).toString("base64url"),
			KEY_OF_32.replace(/=+$/, ""),
		]) {
			await expect(
				redisFederationTokenStoreBuilder(
					{
						deploymentMode: "unset",
						client: fakeClient(),
						encryption: { mode: "required", key },
					},
					{},
				),
				JSON.stringify(key),
			).rejects.toThrow(new RangeError(MESSAGE_KEY));
		}
		// The canonical spelling, and 32 bytes handed over as a Buffer, build.
		for (const key of [KEY_OF_32, Buffer.alloc(32, 0xfb)]) {
			const store = (await redisFederationTokenStoreBuilder(
				{
					deploymentMode: "unset",
					client: fakeClient(),
					encryption: { mode: "required", key },
				},
				{},
			)) as { kind: string };
			expect(store.kind).toBe("redis");
		}
	});

	it("refuses an encryption mode it does not know, rather than reading it as plaintext", async () => {
		// A typo such as "requried" must not be taken for `allow-plaintext`,
		// which stores in the clear with a warning outside production, and is
		// refused in production with a message about plaintext the operator
		// never asked for.
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const message = '[federation-tokens] mode must be "required" or "allow-plaintext"';
			await expect(
				redisFederationTokenStoreBuilder(
					{
						deploymentMode: "unset",
						client: fakeClient(),
						encryption: { mode: "requried", key: KEY_OF_32 },
					},
					{},
				),
			).rejects.toThrow(new RangeError(message));
			await expect(
				createRedisFederationTokenStore({
					deploymentMode: "unset",
					client: fakeClient() as unknown as FederationTokenStoreClient,
					encryption: { mode: "requried" } as never,
				}),
			).rejects.toThrow(new RangeError(message));
			expect(warn).not.toHaveBeenCalled();
		} finally {
			warn.mockRestore();
		}
	});

	it("through the builder: a configured key that does not decode to 32 bytes, or none", async () => {
		const message = MESSAGE_KEY;
		for (const key of [KEY_OF_16, Buffer.alloc(16, 7), undefined]) {
			await expect(
				redisFederationTokenStoreBuilder(
					{
						deploymentMode: "unset",
						client: fakeClient(),
						encryption: { mode: "required", key },
					},
					{},
				),
				String(key),
			).rejects.toThrow(new RangeError(message));
		}
	});

	it.each([
		[
			"a key that does not decode to 32 bytes",
			{ "redis-federation-token-store": { encryptionKey: KEY_OF_16 } },
			"federationTokenStore.redis: encryption.key must be canonical base64 of 32 bytes (AES-256), or a Buffer of 32 bytes, when encryption.mode is 'required' (the default)",
		],
		[
			"a key that is not canonical base64",
			{ "redis-federation-token-store": { encryptionKey: `${KEY_OF_32}\n` } },
			"federationTokenStore.redis: encryption.key must be canonical base64 of 32 bytes (AES-256), or a Buffer of 32 bytes, when encryption.mode is 'required' (the default)",
		],
		[
			"no key under the default mode",
			{ "redis-federation-token-store": {} },
			"federationTokenStore.redis: encryption.key must be canonical base64 of 32 bytes (AES-256), or a Buffer of 32 bytes, when encryption.mode is 'required' (the default)",
		],
		[
			'plaintext under core.deployment.mode = "multi"',
			{
				"redis-federation-token-store": { encryptionMode: "allow-plaintext" },
				core: { deployment: { mode: "multi" } },
			},
			PLAINTEXT_UNDER_MULTI,
		],
	])("at boot: %s is the BootError's cause, as a RangeError", async (_what, extra, message) => {
		const cause = await bootRefusal(extra);
		expect(cause).toStrictEqual(new RangeError(message));
		expect(cause).toBeInstanceOf(RangeError);
	});

	it("leaves a missing client an Error: a composition fault, refused as every Redis builder refuses it", async () => {
		// Not a setting that is given and unusable, but a dependency that was not
		// given; the module path never reaches it (`requires` refuses first).
		const thrown = await Promise.resolve(
			redisFederationTokenStoreBuilder({ deploymentMode: "unset" }, {}),
		).catch((err: unknown) => err);
		expect((thrown as Error).constructor).toBe(Error);
		expect((thrown as Error).message).toBe(
			"federationTokenStore.redis: 'client' option is required",
		);
	});
});
