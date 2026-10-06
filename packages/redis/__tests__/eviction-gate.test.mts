/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The one eviction gate every Redis store whose keys must stay until they
 * expire runs before it is handed out — the attempt counter, the session
 * lifecycle store, the federation token store and the two MFA stores — on
 * every path that builds one: the exported factory, the module and, for the
 * federation token store, the adapter builder.
 *
 * A store is built only on a server whose `maxmemory-policy` reads as
 * `noeviction`. Any other policy it reads refuses, known or not. A policy it
 * cannot read refuses unless the client reports the operator's
 * `assumeNoEviction` assertion, which a policy the server does report always
 * overrides. A server that cannot answer fails the build.
 */

import { Buffer } from "node:buffer";
import type { Module } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import { describe, expect, it } from "vitest";
import { createRedisAttemptCounter, redisAttemptCounterModule } from "#/attempt-counter.mjs";
import type { RedisDurability } from "#/clients.mjs";
import {
	createRedisFederationTokenStore,
	redisFederationTokenStoreBuilder,
	redisFederationTokenStoreModule,
} from "#/federation-tokens.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { createRedisMfaFactorStore, redisMfaFactorStoreModule } from "#/mfa-factor-store.mjs";
import {
	createRedisMfaTransactionStore,
	redisMfaTransactionStoreModule,
} from "#/mfa-transaction-store.mjs";
import { redisSessionStoresModule } from "#/modules/redisSessionStores.mjs";
import { createRedisSessionLifecycleStore } from "#/session-lifecycle-store.mjs";
import { withSection } from "./support/section.mjs";

/** A client that answers `durability` as given, and every other member with nothing. */
const clientReporting = (durability: () => Promise<RedisDurability>): never =>
	new Proxy(
		{ durability },
		{
			get: (target, key) =>
				key in target
					? target[key as keyof typeof target]
					: key === "then"
						? undefined
						: async () => undefined,
		},
	) as never;

const KEY = Buffer.alloc(32, 7);

/** Runs `module`'s provider for `slot` over `deps`, its section parsed from `config`. */
const provide = (
	module: Module,
	slot: string,
	deps: Record<string, unknown>,
	config: Record<string, unknown> = {},
): Promise<unknown> => {
	const provider = (module.provides as Record<string, unknown> | undefined)?.[slot] as
		| ((deps: unknown) => unknown)
		| undefined;
	if (provider === undefined) throw new Error(`${module.name} provides no ${slot}`);
	return Promise.resolve().then(() => provider(withSection(module, { ...deps, config })));
};

interface Path {
	readonly name: string;
	readonly build: (client: never) => Promise<unknown>;
}

interface Store {
	readonly store: string;
	readonly reason: string;
	readonly paths: readonly Path[];
}

const STORES: readonly Store[] = [
	{
		store: "attemptCounter",
		reason: "attempt-counter-evictable",
		paths: [
			{
				name: "createRedisAttemptCounter",
				build: (client) => createRedisAttemptCounter({ client }),
			},
			{
				name: "redisAttemptCounterModule",
				build: (client) =>
					provide(redisAttemptCounterModule, "attemptCounter", { attemptCounterClient: client }),
			},
		],
	},
	{
		store: "sessionLifecycleStore",
		reason: "session-lifecycle-store-evictable",
		paths: [
			{
				name: "createRedisSessionLifecycleStore",
				build: (client) => createRedisSessionLifecycleStore({ client }),
			},
			{
				name: "redisSessionStoresModule",
				build: (client) =>
					provide(redisSessionStoresModule, "sessionLifecycleStore", {
						sessionLifecycleStoreClient: client,
					}),
			},
		],
	},
	{
		store: "federationTokenStore",
		reason: "federation-token-store-evictable",
		paths: [
			{
				name: "createRedisFederationTokenStore",
				build: (client) =>
					createRedisFederationTokenStore({
						client,
						encryption: { mode: "required", key: KEY },
						deploymentMode: "unset",
					}),
			},
			{
				name: "redisFederationTokenStoreBuilder",
				build: (client) =>
					Promise.resolve(
						redisFederationTokenStoreBuilder(
							{ client, encryption: { mode: "required", key: KEY }, deploymentMode: "unset" },
							{},
						),
					),
			},
			{
				name: "redisFederationTokenStoreModule",
				build: (client) =>
					provide(
						redisFederationTokenStoreModule,
						"federationTokenStore",
						{ federationTokenStoreClient: client, deploymentMode: "unset" },
						{ "redis-federation-token-store": { encryptionKey: KEY.toString("base64") } },
					),
			},
		],
	},
	{
		store: "mfaFactorStore",
		reason: "mfa-factor-store-evictable",
		paths: [
			{
				name: "createRedisMfaFactorStore",
				build: (client) => createRedisMfaFactorStore({ client }),
			},
			{
				name: "redisMfaFactorStoreModule",
				build: (client) =>
					provide(redisMfaFactorStoreModule, "mfaFactorStore", { mfaFactorStoreClient: client }),
			},
		],
	},
	{
		store: "mfaTransactionStore",
		reason: "mfa-transaction-store-evictable",
		paths: [
			{
				name: "createRedisMfaTransactionStore",
				build: (client) => createRedisMfaTransactionStore({ client }),
			},
			{
				name: "redisMfaTransactionStoreModule",
				build: (client) =>
					provide(redisMfaTransactionStoreModule, "mfaTransactionStore", {
						mfaTransactionStoreClient: client,
					}),
			},
		],
	},
];

const CASES = STORES.flatMap((s) => s.paths.map((path) => ({ ...s, path })));

const report = (
	maxmemoryPolicy: string | undefined,
	extra: Partial<RedisDurability> = {},
): RedisDurability => ({
	maxmemoryPolicy,
	appendOnly: true,
	snapshots: undefined,
	refusal: undefined,
	...extra,
});

/** A reply error as ioredis raises one. */
const replyError = (message: string): Error =>
	Object.assign(new Error(message), { name: "ReplyError" });

const NOPERM = replyError("NOPERM this user has no permissions to run the 'info' command");

const build = (path: Path, answer: RedisDurability | (() => Promise<RedisDurability>)) =>
	path.build(clientReporting(typeof answer === "function" ? answer : async () => answer));

describe.each(CASES)("$path.name", ({ path, store, reason }) => {
	it("builds on a server that reads as noeviction", async () => {
		await expect(build(path, report("noeviction"))).resolves.toBeDefined();
	});

	it.each([
		"volatile-lru",
		"volatile-lfu",
		"volatile-random",
		"volatile-ttl",
		"allkeys-lru",
		"allkeys-lfu",
		"allkeys-random",
		"allkeys-lrm",
		"",
		"NOEVICTION",
	])("refuses any other policy it reads (%j), naming it", async (policy) => {
		const refused = build(path, report(policy));
		await expect(refused).rejects.toMatchObject({
			name: "RedisStoreEvictableError",
			reason,
			maxmemoryPolicy: policy,
		});
		await expect(refused).rejects.toThrow(new RegExp(`^${store}: .*\\(${reason}\\)$`));
	});

	it("refuses a policy it cannot read", async () => {
		for (const unread of [report(undefined, { refusal: NOPERM }), report(undefined)]) {
			await expect(build(path, unread)).rejects.toMatchObject({
				name: "RedisStoreEvictableError",
				reason,
				maxmemoryPolicy: undefined,
			});
		}
		await expect(build(path, report(undefined, { refusal: NOPERM }))).rejects.toThrow(
			/could not be read.*assumeNoEviction/,
		);
	});

	it("builds on a policy it cannot read when the client assumes noeviction", async () => {
		await expect(
			build(path, report(undefined, { refusal: NOPERM, assumeNoEviction: true })),
		).resolves.toBeDefined();
	});

	it.each(["allkeys-lru", "volatile-lru", "allkeys-lrm"])(
		"refuses a policy the server reports (%s) whatever the client assumes",
		async (policy) => {
			await expect(build(path, report(policy, { assumeNoEviction: true }))).rejects.toMatchObject({
				reason,
				maxmemoryPolicy: policy,
			});
		},
	);

	it("fails the build when the server cannot answer", async () => {
		const outage = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:6379"), {
			code: "ECONNREFUSED",
		});
		await expect(build(path, () => Promise.reject(outage))).rejects.toBe(outage);
	});
});

describe("makeIoredisClients' assumeNoEviction", () => {
	/** A connection that refuses INFO and CONFIG, as an ACL-restricted user's does. */
	const refusing = {
		info: async () => {
			throw NOPERM;
		},
		config: async () => {
			throw NOPERM;
		},
	} as unknown as Redis;

	const durabilityOf = (clients: ReturnType<typeof makeIoredisClients>) => [
		clients.attemptCounterClient.durability(),
		clients.sessionLifecycleStoreClient.durability(),
		clients.federationTokenStoreClient.durability(),
		clients.mfaFactorStoreClient.durability(),
		clients.mfaTransactionStoreClient.durability(),
	];

	it("reaches every client whose store runs the gate", async () => {
		for (const answered of await Promise.all(
			durabilityOf(makeIoredisClients(refusing, { assumeNoEviction: true })),
		)) {
			expect(answered).toMatchObject({ maxmemoryPolicy: undefined, assumeNoEviction: true });
		}
	});

	it("is not reported where it was not given", async () => {
		for (const answered of await Promise.all(durabilityOf(makeIoredisClients(refusing)))) {
			expect(answered).not.toHaveProperty("assumeNoEviction");
		}
	});
});
