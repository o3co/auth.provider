/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The one eviction gate every Redis store whose keys must stay until they
 * expire runs before it is handed out — the attempt counter, the session
 * lifecycle store, the federation token store, the two MFA stores, the
 * stores that hold revocation state (the access-token denylist, subject
 * revocation and the refresh-token family store) and the replay seen-set — on
 * every path that builds
 * one: the exported factory, the module and, where the store has one, the
 * adapter builder.
 *
 * A store is built only on a server whose `maxmemory-policy` reads as
 * `noeviction`. Any other policy it reads refuses, known or not. A policy it
 * cannot read refuses unless the client reports the operator's
 * `assumeNoEviction` assertion, which a policy the server does report always
 * overrides. A server that cannot answer fails the build.
 */

import { Buffer } from "node:buffer";
import { createApp, defineModule, type Module } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import type { Redis } from "ioredis";
import { describe, expect, it } from "vitest";
import {
	createRedisAccessTokenDenylist,
	redisAccessTokenDenylistBuilder,
	redisAccessTokenDenylistModule,
} from "#/access-token-denylist.mjs";
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
import {
	createRedisRefreshTokenFamilyStore,
	redisRefreshTokenFamilyStoreBuilder,
	redisRefreshTokenFamilyStoreModule,
} from "#/refresh-token-family.mjs";
import {
	createRedisReplaySeenSet,
	redisReplaySeenSetBuilder,
	redisReplaySeenSetModule,
} from "#/replay-seen-set.mjs";
import { createRedisSessionLifecycleStore } from "#/session-lifecycle-store.mjs";
import {
	createRedisSubjectRevocation,
	redisSubjectRevocationBuilder,
} from "#/subjectRevocation.mjs";
import { capturing, overReference, withSection } from "./support/section.mjs";

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
	{
		store: "accessTokenDenylist",
		reason: "access-token-denylist-evictable",
		paths: [
			{
				name: "createRedisAccessTokenDenylist",
				build: (client) => createRedisAccessTokenDenylist({ client, keyPrefix: "atdeny:" }),
			},
			{
				name: "redisAccessTokenDenylistBuilder",
				build: (client) => Promise.resolve(redisAccessTokenDenylistBuilder({ client }, {})),
			},
			{
				name: "redisAccessTokenDenylistModule",
				build: (client) =>
					provide(redisAccessTokenDenylistModule, "accessTokenDenylist", {
						accessTokenDenylistClient: client,
					}),
			},
		],
	},
	{
		store: "subjectRevocation",
		reason: "subject-revocation-evictable",
		paths: [
			{
				name: "createRedisSubjectRevocation",
				build: (client) => createRedisSubjectRevocation({ client }),
			},
			{
				name: "redisSubjectRevocationBuilder",
				build: (client) => Promise.resolve(redisSubjectRevocationBuilder({ client }, {})),
			},
			{
				name: "redisSessionStoresModule",
				build: (client) =>
					provide(redisSessionStoresModule, "subjectRevocation", {
						subjectRevocationClient: client,
					}),
			},
		],
	},
	{
		store: "refreshTokenFamilyStore",
		reason: "refresh-token-family-store-evictable",
		paths: [
			{
				name: "createRedisRefreshTokenFamilyStore",
				build: (client) => createRedisRefreshTokenFamilyStore({ client, keyPrefix: "rtfam:" }),
			},
			{
				name: "redisRefreshTokenFamilyStoreBuilder",
				build: (client) => Promise.resolve(redisRefreshTokenFamilyStoreBuilder({ client }, {})),
			},
			{
				name: "redisRefreshTokenFamilyStoreModule",
				build: (client) =>
					provide(redisRefreshTokenFamilyStoreModule, "refreshTokenFamilyStore", {
						refreshTokenFamilyClient: client,
					}),
			},
		],
	},
	{
		store: "replaySeenSet",
		reason: "replay-seen-set-evictable",
		paths: [
			{
				name: "createRedisReplaySeenSet",
				build: (client) => createRedisReplaySeenSet({ client, keyPrefix: "replay:" }),
			},
			{
				name: "redisReplaySeenSetBuilder",
				build: (client) => Promise.resolve(redisReplaySeenSetBuilder({ client }, {})),
			},
			{
				name: "redisReplaySeenSetModule",
				build: (client) =>
					provide(redisReplaySeenSetModule, "replaySeenSet", { replaySeenSetClient: client }),
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

describe.each([
	{
		module: redisAccessTokenDenylistModule,
		slot: "accessTokenDenylist",
		clientSlots: ["accessTokenDenylistClient"],
		reason: "access-token-denylist-evictable",
	},
	{
		module: redisSessionStoresModule,
		slot: "subjectRevocation",
		clientSlots: [
			"userSessionStoreClient",
			"subjectSessionIndexClient",
			"subjectRevocationClient",
			"sessionLifecycleStoreClient",
		],
		reason: "subject-revocation-evictable",
	},
	{
		module: redisRefreshTokenFamilyStoreModule,
		slot: "refreshTokenFamilyStore",
		clientSlots: ["refreshTokenFamilyClient"],
		reason: "refresh-token-family-store-evictable",
	},
	{
		module: redisReplaySeenSetModule,
		slot: "replaySeenSet",
		clientSlots: ["replaySeenSetClient"],
		reason: "replay-seen-set-evictable",
	},
])("a boot that reads $slot from $module.name", ({ module, slot, clientSlots, reason }) => {
	/** Reads the slot and contributes a route, so the slot is built at boot. */
	const reader = defineModule({
		name: `test:${slot}-reader`,
		requires: [slot] as never,
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

	const boot = (answer: RedisDurability) =>
		createApp({
			modules: [module, reader],
			bootstrapComponents: {
				config: capturing(overReference(makeValidCoreConfig(), [module]), [module]),
				pathResolver: (p: string) => p,
				...Object.fromEntries(clientSlots.map((c) => [c, clientReporting(async () => answer)])),
			} as never,
		});

	it("is refused on a server that may evict, naming the module and the store", async () => {
		await expect(boot(report("allkeys-lru"))).rejects.toMatchObject({
			name: "BootError",
			reason: "provides-factory-failed",
			details: { module: module.name, componentKey: slot },
			cause: { name: "RedisStoreEvictableError", reason, maxmemoryPolicy: "allkeys-lru" },
		});
	});

	it("boots on noeviction, and on a policy it cannot read when the clients assume noeviction", async () => {
		for (const answer of [
			report("noeviction"),
			report(undefined, { refusal: NOPERM, assumeNoEviction: true }),
		]) {
			const handle = await boot(answer);
			expect((handle.components as Record<string, unknown>)[slot]).toBeDefined();
			await handle.dispose();
		}
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
		clients.accessTokenDenylistClient.durability(),
		clients.subjectRevocationClient.durability(),
		clients.refreshTokenFamilyClient.durability(),
		clients.replaySeenSetClient.durability(),
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

describe("the policy the bundled clients read off the server", () => {
	/** Each store's client in `makeIoredisClients`, by the store's name in STORES. */
	const CLIENT_OF: Readonly<Record<string, keyof ReturnType<typeof makeIoredisClients>>> = {
		attemptCounter: "attemptCounterClient",
		sessionLifecycleStore: "sessionLifecycleStoreClient",
		federationTokenStore: "federationTokenStoreClient",
		mfaFactorStore: "mfaFactorStoreClient",
		mfaTransactionStore: "mfaTransactionStoreClient",
		accessTokenDenylist: "accessTokenDenylistClient",
		subjectRevocation: "subjectRevocationClient",
		refreshTokenFamilyStore: "refreshTokenFamilyClient",
		replaySeenSet: "replaySeenSetClient",
	};

	/** A connection whose INFO memory and CONFIG GET maxmemory-policy answer as given; an Error is thrown. */
	const answering = (memory: unknown, policy: unknown): Redis =>
		({
			info: async (section: string) => {
				const reply = section === "memory" ? memory : "# Persistence\r\naof_enabled:1\r\n";
				if (reply instanceof Error) throw reply;
				return reply;
			},
			config: async () => {
				if (policy instanceof Error) throw policy;
				return policy;
			},
		}) as unknown as Redis;

	/** Builds every store through its factory over `io`'s bundled clients. */
	const buildAll = (io: Redis, assumeNoEviction?: boolean) => {
		const clients = makeIoredisClients(
			io,
			assumeNoEviction === undefined ? {} : { assumeNoEviction },
		);
		return STORES.map((s) => ({
			store: s.store,
			reason: s.reason,
			built: (s.paths[0] as Path).build(clients[CLIENT_OF[s.store] as never] as never),
		}));
	};

	it.each([
		["an array", ["maxmemory-policy", "allkeys-lru"]],
		["a map object", { "maxmemory-policy": "allkeys-lru" }],
		["a Map", new Map([["maxmemory-policy", "allkeys-lru"]])],
	])(
		"refuses a policy CONFIG GET reports as %s, whatever the client assumes",
		async (_shape, reply) => {
			for (const assume of [undefined, true]) {
				for (const { store, reason, built } of buildAll(answering(NOPERM, reply), assume)) {
					await expect(built, store).rejects.toMatchObject({
						reason,
						maxmemoryPolicy: "allkeys-lru",
					});
				}
			}
		},
	);

	it.each([
		["an array", ["maxmemory-policy", "noeviction"]],
		["a map object", { "maxmemory-policy": "noeviction" }],
		["a Map", new Map([["maxmemory-policy", "noeviction"]])],
	])("builds on noeviction CONFIG GET reports as %s", async (_shape, reply) => {
		for (const { store, built } of buildAll(answering(NOPERM, reply))) {
			await expect(built, store).resolves.toBeDefined();
		}
	});

	it.each([
		["a string", "allkeys-lru"],
		["a number", 7],
		["null", null],
		["an array naming another parameter", ["maxmemory", "allkeys-lru"]],
		["an array of odd length", ["maxmemory-policy"]],
		["an array whose value is no string", ["maxmemory-policy", 1]],
		["a map naming another parameter", { maxmemory: "0" }],
		["a map whose value is no string", { "maxmemory-policy": ["allkeys-lru"] }],
	])(
		"fails the build on a CONFIG GET reply it does not recognise (%s), never reading it as unread",
		async (_shape, reply) => {
			for (const { store, built } of buildAll(answering(NOPERM, reply), true)) {
				await expect(built, store).rejects.toThrow(/CONFIG GET maxmemory-policy/);
			}
		},
	);

	it("reads an empty CONFIG GET reply as a policy it could not read", async () => {
		for (const reply of [[], {}, new Map()]) {
			for (const { store, reason, built } of buildAll(answering(NOPERM, reply))) {
				await expect(built, store).rejects.toMatchObject({ reason, maxmemoryPolicy: undefined });
			}
		}
	});

	it.each([
		["noeviction, then allkeys-lru", "maxmemory_policy:noeviction\r\nmaxmemory_policy:allkeys-lru"],
		["allkeys-lru, then noeviction", "maxmemory_policy:allkeys-lru\r\nmaxmemory_policy:noeviction"],
		["noeviction, then an empty value", "maxmemory_policy:noeviction\r\nmaxmemory_policy:"],
	])(
		"fails the build on an INFO memory reply that names the policy twice, differently (%s), whatever the client assumes",
		async (_label, lines) => {
			for (const assume of [undefined, true]) {
				const io = answering(`# Memory\r\n${lines}\r\n`, ["maxmemory-policy", "noeviction"]);
				for (const { store, built } of buildAll(io, assume)) {
					await expect(built, store).rejects.toThrow(/INFO memory/);
				}
			}
		},
	);

	it("builds on an INFO memory reply that names noeviction twice", async () => {
		const io = answering(
			"# Memory\r\nmaxmemory_policy:noeviction\r\nmaxmemory_policy:noeviction\r\n",
			NOPERM,
		);
		for (const { store, built } of buildAll(io)) {
			await expect(built, store).resolves.toBeDefined();
		}
	});

	it("fails the build on an INFO memory reply that is no text", async () => {
		for (const reply of [7, { maxmemory_policy: "noeviction" }, ["maxmemory_policy:noeviction"]]) {
			for (const { store, built } of buildAll(answering(reply, NOPERM), true)) {
				await expect(built, store).rejects.toThrow(/INFO memory/);
			}
		}
	});
});
