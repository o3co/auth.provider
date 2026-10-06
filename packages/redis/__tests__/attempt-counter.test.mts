/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The Redis `AttemptCounter` against test-kit's `attemptCounterContract` on a
 * real Redis, on a hand-moved clock and on the real one, and what the Redis
 * adapter adds: its own key namespace, the key's lifetime on the counter's
 * clock, a refused attempt writing nothing, a reply that is no count rejected,
 * and the gate its factory and module pass, which refuses a server that may
 * evict a running window.
 */

import {
	type AppConfig,
	ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
	type AttemptCounter,
	type AttemptSpec,
	createApp,
	defineModule,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import {
	type AttemptCounterContractInput,
	type AttemptCounterHarness,
	attemptCounterContract,
} from "@o3co/auth-provider-test-kit";
import { Redis } from "ioredis";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
	createRedisAttemptCounter,
	DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX,
	redisAttemptCounterModule,
} from "#/attempt-counter.mjs";
import type {
	AttemptCounterClient,
	AttemptCounterConsumeReply,
	RedisDurability,
} from "#/clients.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { testRedis } from "./support/redis.mjs";

let connections: Redis[] = [];
let run = 0;

beforeAll(async () => {
	const at = await testRedis();
	connections = [new Redis(at), new Redis(at)];
});

afterAll(async () => {
	await Promise.all(connections.map((connection) => connection.quit()));
});

afterEach(() => {
	vi.restoreAllMocks();
});

/** A server that keeps what it is written: what a stub client reports unless a case says otherwise. */
const DURABLE: RedisDurability = {
	maxmemoryPolicy: "noeviction",
	appendOnly: true,
	snapshots: undefined,
	refusal: undefined,
};

/** A client that reports `durability` and is asked nothing else. */
const unaskedClient = (
	durability: RedisDurability | (() => Promise<RedisDurability>) = DURABLE,
): AttemptCounterClient => ({
	consume: async () => {
		throw new Error("consume was not expected");
	},
	durability: typeof durability === "function" ? durability : async () => durability,
});

const first = (): Redis => connections[0] as Redis;
const second = (): Redis => connections[1] as Redis;

const freshPrefix = (): string => {
	run += 1;
	return `attempt:test-${run}:`;
};

/** A counter over `connection`; `durable` stands in for a server that cannot answer the gate. */
const counterAt = (
	keyPrefix: string,
	connection: Redis,
	now?: () => number,
	durable = false,
): Promise<AttemptCounter> => {
	const client = makeIoredisClients(connection).attemptCounterClient;
	return createRedisAttemptCounter({
		client: durable ? { ...client, durability: async () => DURABLE } : client,
		keyPrefix,
		...(now === undefined ? {} : { now }),
	});
};

/** A clock the harness moves by hand, for the counter and for the server's countdowns, starting at the host's time. */
const handClock = (prefix: string) => {
	let now = Date.now();
	return {
		now: () => now,
		/**
		 * Lets `ms` pass for the server's countdowns too: each key under `prefix`
		 * loses `ms` of its TTL, as it would have on a server whose time moved.
		 */
		advance: async (ms: number) => {
			now += ms;
			for (const key of await first().keys(`${prefix}*`)) {
				const pttl = await first().pttl(key);
				if (pttl <= 0) continue;
				if (pttl > ms) await first().pexpire(key, pttl - ms);
				else await first().del(key);
			}
		},
	};
};

const harness = (clocked: boolean) => async (): Promise<AttemptCounterHarness> => {
	const prefix = freshPrefix();
	const clock = clocked ? handClock(prefix) : undefined;
	const io = new Redis({
		host: "127.0.0.1",
		port: 1,
		lazyConnect: true,
		enableOfflineQueue: false,
		maxRetriesPerRequest: 0,
		retryStrategy: () => null,
	});
	io.on("error", () => {});
	const unreachable = await counterAt(prefix, io, clock?.now, true);
	return {
		counter: await counterAt(prefix, first(), clock?.now),
		second: await counterAt(prefix, second(), clock?.now),
		...(clock === undefined ? {} : { clock }),
		unreachable: () => unreachable,
		close: async () => {
			io.disconnect();
		},
	};
};

const contract = (name: string, input: AttemptCounterContractInput): void => {
	describe(name, () => {
		for (const contractCase of attemptCounterContract(input)) {
			it(contractCase.name, contractCase.run);
		}
	});
};

contract("attemptCounterContract over the Redis counter on a hand-moved clock", {
	build: harness(true),
	supports: { unreachable: true },
});

contract("attemptCounterContract over the Redis counter on the real clock", {
	build: harness(false),
	supports: { unreachable: true },
});

describe("createRedisAttemptCounter on Redis", () => {
	const SPEC: AttemptSpec = { limit: 2, windowSeconds: 60 };

	it(`keys its windows under "${DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX}" by default, apart from the rate limiter's keys of the same form`, async () => {
		const key = `login:ip:192.0.2.${run + 100}`;
		const clients = makeIoredisClients(first());
		const counter = await createRedisAttemptCounter({ client: clients.attemptCounterClient });
		await counter.consume(key, SPEC);
		expect(await first().exists(`${DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX}${key}`)).toBe(1);
		expect(await first().exists(key)).toBe(0);
		await expect(clients.rateLimiterClient.incrementWithTtl(key, 60)).resolves.toBe(1);
		const next = await counter.consume(key, SPEC);
		expect([next.allowed, next.remaining]).toEqual([true, 0]);
	});

	it.each([
		["an hour ahead of", 3_600_000],
		["level with", 0],
		["an hour behind", -3_600_000],
	])(
		"gives a window's key the window's remaining time plus the clock allowance, the counter's clock %s the server's",
		async (_label, offset) => {
			const prefix = freshPrefix();
			const now = Date.now() + offset;
			const counter = await counterAt(prefix, first(), () => now);
			const count = await counter.consume("k", SPEC);
			expect(count.resetAt.getTime()).toBe(now + 60_000);
			const lifetime = 60_000 + ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS;
			const pttl = await first().pttl(`${prefix}k`);
			expect(pttl).toBeLessThanOrEqual(lifetime);
			expect(pttl).toBeGreaterThan(lifetime - 2_000);
		},
	);

	it("keeps a running window's key through a later attempt, on a counter clock far behind the server's", async () => {
		const prefix = freshPrefix();
		let now = Date.now() - 3_600_000;
		const counter = await counterAt(prefix, first(), () => now);
		await counter.consume("k", SPEC);
		now += 30_000;
		const second = await counter.consume("k", SPEC);
		expect([second.allowed, second.remaining]).toEqual([true, 0]);
		expect((await counter.consume("k", SPEC)).allowed).toBe(false);
	});

	it("writes nothing for a refused attempt, and keeps the window's end and deadline when a later spec changes the window", async () => {
		const prefix = freshPrefix();
		const key = `${prefix}k`;
		let now = Date.now();
		const counter = await counterAt(prefix, first(), () => now);
		await counter.consume("k", SPEC);
		await counter.consume("k", SPEC);
		const before = [await first().hgetall(key), await first().pexpiretime(key)];
		now += 1_000;
		const refused = await counter.consume("k", { limit: 2, windowSeconds: 600 });
		expect(refused.allowed).toBe(false);
		expect([await first().hgetall(key), await first().pexpiretime(key)]).toEqual(before);
		const raised = await counter.consume("k", { limit: 3, windowSeconds: 1 });
		expect(raised.allowed).toBe(true);
		expect(await first().pexpiretime(key)).toBe(before[1]);
	});

	describe("two replicas whose clocks stand apart, on one Redis", () => {
		const WINDOW: AttemptSpec = { limit: 3, windowSeconds: 20 };

		const replicas = async (aheadMs: number) => {
			const prefix = freshPrefix();
			const at = Date.now();
			return {
				prefix,
				at,
				behind: await counterAt(prefix, first(), () => at),
				ahead: await counterAt(prefix, second(), () => at + aheadMs),
			};
		};

		it("a replica 30 s ahead never reopens a window the server still runs: its attempt is answered no count, and the window keeps its end and count", async () => {
			const { prefix, at, behind, ahead } = await replicas(30_000);
			const opened = await behind.consume("k", WINDOW);
			expect(opened.resetAt.getTime()).toBe(at + 20_000);
			await expect(ahead.consume("k", WINDOW)).rejects.toThrow(/answered no count/);
			expect(await first().hgetall(`${prefix}k`)).toEqual({
				count: "2",
				resetAt: String(at + 20_000),
			});
			const next = await behind.consume("k", WINDOW);
			expect([next.allowed, next.remaining]).toEqual([true, 0]);
			expect((await behind.consume("k", WINDOW)).allowed).toBe(false);
		});

		it("a replica ahead by less than the clock allowance past the window's end is counted in the running window, answered its end", async () => {
			const { at, behind, ahead } = await replicas(23_000);
			await behind.consume("k", WINDOW);
			const skewed = await ahead.consume("k", WINDOW);
			expect([skewed.allowed, skewed.remaining, skewed.resetAt.getTime()]).toEqual([
				true,
				1,
				at + 20_000,
			]);
		});
	});

	it("rejects an attempt whose key holds another type, counting nothing", async () => {
		const prefix = freshPrefix();
		await first().set(`${prefix}k`, "x");
		await expect((await counterAt(prefix, first())).consume("k", SPEC)).rejects.toThrow(
			/WRONGTYPE/,
		);
		expect(await first().get(`${prefix}k`)).toBe("x");
	});
});

describe("createRedisAttemptCounter over a client whose reply is no count", () => {
	const SPEC: AttemptSpec = { limit: 3, windowSeconds: 60 };
	const NOW = Date.parse("2026-10-03T00:00:00.000Z");

	const answering = (reply: unknown): AttemptCounterClient => ({
		...unaskedClient(),
		consume: async () => reply as AttemptCounterConsumeReply,
	});

	const good: AttemptCounterConsumeReply = { allowed: true, count: 1, resetAtMs: NOW + 60_000 };

	it("answers a good reply as the count it is", async () => {
		const counter = await createRedisAttemptCounter({ client: answering(good), now: () => NOW });
		const count = await counter.consume("k", SPEC);
		expect([count.allowed, count.remaining, count.resetAt.getTime()]).toEqual([
			true,
			2,
			NOW + 60_000,
		]);
	});

	it.each([
		["nothing", undefined],
		["null", null],
		["a number", 1],
		["allowed not a boolean", { ...good, allowed: 1 }],
		["a count that is not whole", { ...good, count: 1.5 }],
		["a count below 1", { ...good, count: 0 }],
		["an allowed count past the limit", { ...good, count: 4 }],
		["a refused count under the limit", { ...good, allowed: false, count: 2 }],
		["a window's end that is not a number", { ...good, resetAtMs: "1" }],
		["a window's end already past", { ...good, resetAtMs: NOW - 10_000 }],
		["a window's end past the longest window", { ...good, resetAtMs: NOW + 86_400_000 + 10_000 }],
	])("rejects %s", async (_label, reply) => {
		const counter = await createRedisAttemptCounter({ client: answering(reply), now: () => NOW });
		await expect(counter.consume("k", SPEC)).rejects.toThrow(/createRedisAttemptCounter/);
	});

	it("rejects a clock that answers no instant, asking nothing", async () => {
		let asked = 0;
		const client: AttemptCounterClient = {
			...unaskedClient(),
			consume: async () => {
				asked += 1;
				return good;
			},
		};
		// The last instant a Date holds: a window opened there would end past the range.
		for (const now of [Number.NaN, Number.POSITIVE_INFINITY, -1, 8_640_000_000_000_000]) {
			const counter = await createRedisAttemptCounter({ client, now: () => now });
			await expect(counter.consume("k", SPEC)).rejects.toThrow(RangeError);
		}
		expect(asked).toBe(0);
	});

	it("refuses an empty key prefix at construction, before it asks the server", async () => {
		const durability = vi.fn(async () => DURABLE);
		await expect(
			createRedisAttemptCounter({ client: { ...answering(good), durability }, keyPrefix: "" }),
		).rejects.toThrow(RangeError);
		expect(durability).not.toHaveBeenCalled();
	});

	it("hands the client the prefixed key, the caller's clock, the limit, the window's end and the clock allowance", async () => {
		const seen: unknown[] = [];
		const client: AttemptCounterClient = {
			...unaskedClient(),
			consume: async (key, input) => {
				seen.push([key, input]);
				return good;
			},
		};
		const counter = await createRedisAttemptCounter({
			client,
			keyPrefix: "p:",
			now: () => NOW + 0.7,
		});
		await counter.consume("login:ip:192.0.2.1", SPEC);
		expect(seen).toEqual([
			[
				"p:login:ip:192.0.2.1",
				{
					nowMs: NOW,
					limit: 3,
					resetAtMs: NOW + 60_000,
					expiryAllowanceMs: ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
				},
			],
		]);
	});
});

/** A reply error as ioredis raises one. */
const replyError = (message: string): Error =>
	Object.assign(new Error(message), { name: "ReplyError" });

describe("redisAttemptCounterModule", () => {
	const provide = (deps: Record<string, unknown>): Promise<AttemptCounter> => {
		const provider = redisAttemptCounterModule.provides?.attemptCounter;
		if (provider === undefined) throw new Error("redis-attempt-counter provides no attemptCounter");
		return (provider as unknown as (deps: unknown) => Promise<AttemptCounter>)({
			section: { keyPrefix: "attempt:" },
			...deps,
		});
	};

	const boot = (durability: RedisDurability | (() => Promise<RedisDurability>)) =>
		provide({ attemptCounterClient: unaskedClient(durability) });

	it("has the canonical name, and requires attemptCounterClient alone", () => {
		expect(redisAttemptCounterModule.name).toBe("redis-attempt-counter");
		expect(redisAttemptCounterModule.requires).toEqual(["attemptCounterClient"]);
		expect(redisAttemptCounterModule.optional).toBeUndefined();
	});

	it(`reads its own section, 'redis-attempt-counter', strict, whose keyPrefix defaults to '${DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX}'`, () => {
		const schema = redisAttemptCounterModule.section?.schema;
		expect(redisAttemptCounterModule.section).not.toHaveProperty("at");
		expect(schema?.parse(undefined)).toEqual({ keyPrefix: "attempt:" });
		expect(schema?.safeParse({ keyPrefx: "a:" }).success).toBe(false);
		expect(schema?.safeParse({ keyPrefix: "" }).success).toBe(false);
	});

	it("fills the attemptCounter slot with a counter keyed under the section's prefix", async () => {
		const keys: string[] = [];
		const attemptCounterClient: AttemptCounterClient = {
			...unaskedClient(),
			consume: async (key, input) => {
				keys.push(key);
				return { allowed: true, count: 1, resetAtMs: input.resetAtMs };
			},
		};
		const counter = await provide({
			section: { keyPrefix: "tenant-a:attempt:" },
			attemptCounterClient,
		});
		await counter.consume("login:ip:192.0.2.1", { limit: 5, windowSeconds: 60 });
		expect(keys).toEqual(["tenant-a:attempt:login:ip:192.0.2.1"]);
	});

	it("boots on noeviction", async () => {
		await expect(boot(DURABLE)).resolves.toBeDefined();
	});

	it.each([
		"allkeys-lru",
		"allkeys-lfu",
		"allkeys-random",
		"volatile-lru",
		"volatile-lfu",
		"volatile-random",
		"volatile-ttl",
		"",
		"lru",
		"NOEVICTION",
	])(
		"refuses %j at boot: any policy but noeviction may evict a running window, whose key carries a TTL",
		async (policy) => {
			const refused = boot({ ...DURABLE, maxmemoryPolicy: policy });
			await expect(refused).rejects.toMatchObject({
				name: "RedisStoreEvictableError",
				reason: "attempt-counter-evictable",
				maxmemoryPolicy: policy,
			});
			await expect(refused).rejects.toThrow(
				/attemptCounter: .*noeviction.*\(attempt-counter-evictable\)$/,
			);
		},
	);

	it("says what a policy may evict in its refusal", async () => {
		await expect(boot({ ...DURABLE, maxmemoryPolicy: "allkeys-lru" })).rejects.toThrow(
			/"allkeys-lru", which may evict any key/,
		);
		await expect(boot({ ...DURABLE, maxmemoryPolicy: "volatile-ttl" })).rejects.toThrow(
			/"volatile-ttl", which may evict any key with a TTL/,
		);
	});

	it("refuses a policy it could not read, naming the refusal as its cause", async () => {
		const refusal = replyError("ERR unknown command 'CONFIG'");
		const refused = boot({
			maxmemoryPolicy: undefined,
			appendOnly: undefined,
			snapshots: undefined,
			refusal,
		});
		await expect(refused).rejects.toMatchObject({
			name: "RedisStoreEvictableError",
			reason: "attempt-counter-evictable",
			maxmemoryPolicy: undefined,
			cause: refusal,
		});
	});

	it("boots on a policy it could not read when the client assumes noeviction", async () => {
		await expect(
			boot({ ...DURABLE, maxmemoryPolicy: undefined, assumeNoEviction: true }),
		).resolves.toBeDefined();
	});

	it("fails the boot when the server cannot be asked at all: an outage is not a refusal", async () => {
		const outage = new Error("Connection is closed.");
		await expect(boot(() => Promise.reject(outage))).rejects.toBe(outage);
	});

	/** Reads the slot, as the attempt guard's callers will, and contributes a route so it is a closure root. */
	const reader = defineModule({
		name: "test:attempt-counter-reader",
		optional: ["attemptCounter"] as const,
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

	it("boots through createApp off the shared clients on the test server, which does not evict", async () => {
		const handle = await createApp({
			modules: [redisAttemptCounterModule, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig() as AppConfig,
				pathResolver: (p: string) => p,
				...makeIoredisClients(first()),
			} as never,
		});
		try {
			const components = handle.components as Record<string, unknown>;
			expect(typeof (components.attemptCounter as AttemptCounter | undefined)?.consume).toBe(
				"function",
			);
		} finally {
			await handle.dispose();
		}
	});

	it("is a refused boot through createApp on a server that may evict, naming the module", async () => {
		const refused = createApp({
			modules: [redisAttemptCounterModule, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig() as AppConfig,
				pathResolver: (p: string) => p,
				attemptCounterClient: unaskedClient({ ...DURABLE, maxmemoryPolicy: "volatile-lru" }),
			} as never,
		});
		await expect(refused).rejects.toMatchObject({
			name: "BootError",
			reason: "provides-factory-failed",
			details: { module: "redis-attempt-counter", componentKey: "attemptCounter" },
			cause: { reason: "attempt-counter-evictable", maxmemoryPolicy: "volatile-lru" },
		});
	});
});
