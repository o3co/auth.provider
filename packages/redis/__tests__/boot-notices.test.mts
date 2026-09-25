/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The notices this package writes while a composition is built — the
 * plaintext guard's on the two stores that hold upstream refresh tokens, and
 * the deprecated code-repository builder's. Each is one object-first line
 * with an event name, at the level it always had, on the logger the
 * composition hands the module (or builder, or store); `consoleLogger`
 * writes the same line when none is handed over.
 *
 * A line that opens with a string is a message, not a structured event: pino
 * treats what follows it as printf arguments, and a query on the event name
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
} as unknown as FederationTokenStoreClient;

const grantClient = {} as FederationGrantStoreClient;

const PLAINTEXT = { mode: "allow-plaintext" } as const;

const TOKEN_STORE_CONFIG = {
	redisFederationTokenStore: {
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

describe("the plaintext guard's notices (#473)", () => {
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

	it("warns once, object-first, where plaintext is allowed", () => {
		const { logger, calls } = recordingLogger();
		createRedisFederationTokenStore({
			client: tokenClient,
			encryption: PLAINTEXT,
			environment: "development",
			deploymentMode: "single",
			logger,
		});
		expect(calls).toEqual([plaintextWarning("federation-tokens")]);
	});

	it("logs once at error, naming what refused it, when the override lets plaintext through", () => {
		process.env.FEDERATION_TOKENS_ALLOW_INSECURE = "1";
		const { logger, calls } = recordingLogger();
		createRedisFederationTokenStore({
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

	it("the token store's builder writes its context's logger, once", () => {
		const { logger, calls } = recordingLogger();
		redisFederationTokenStoreBuilder({ client: tokenClient, encryption: PLAINTEXT }, { logger });
		expect(calls).toEqual([plaintextWarning("federation-tokens")]);
	});

	it("each module writes the composition's logger slot, once", () => {
		const tokens = recordingLogger();
		const provideTokens = redisFederationTokenStoreModuleFor().provides?.federationTokenStore as (
			deps: unknown,
		) => unknown;
		provideTokens({
			federationTokenStoreClient: tokenClient,
			config: TOKEN_STORE_CONFIG,
			logger: tokens.logger,
		});
		expect(tokens.calls).toEqual([plaintextWarning("federation-tokens")]);

		const grants = recordingLogger();
		const provideGrants = redisFederationGrantStoreModuleFor().provides?.federationGrantStore as (
			deps: unknown,
		) => unknown;
		provideGrants({
			federationGrantStoreClient: grantClient,
			config: { federationGrants: { encryptionMode: "allow-plaintext" } },
			logger: grants.logger,
		});
		expect(grants.calls).toEqual([plaintextWarning("federation-grants")]);
	});

	it("with no logger handed over, consoleLogger writes the same one line", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		createRedisFederationTokenStore({ client: tokenClient, encryption: PLAINTEXT });
		expect(warn.mock.calls).toEqual([
			[{ store: "federation-tokens", mode: "allow-plaintext" }, "federation_store_plaintext"],
		]);
		expect(error).not.toHaveBeenCalled();
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
