/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The Redis `AttemptCounter` against test-kit's `attemptCounterContract` on a
 * real Redis, on a hand-moved clock and on the real one, and what the Redis
 * adapter adds: its own key namespace, the key's deadline, a refused attempt
 * writing nothing, a reply that is no count rejected, and its module.
 */

import {
	ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
	type AttemptCounter,
	type AttemptSpec,
} from "@o3co/auth-provider-core";
import {
	type AttemptCounterContractInput,
	type AttemptCounterHarness,
	attemptCounterContract,
} from "@o3co/auth-provider-test-kit";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	createRedisAttemptCounter,
	DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX,
	redisAttemptCounterModule,
} from "#/attempt-counter.mjs";
import type { AttemptCounterClient, AttemptCounterConsumeReply } from "#/clients.mjs";
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

const first = (): Redis => connections[0] as Redis;
const second = (): Redis => connections[1] as Redis;

const freshPrefix = (): string => {
	run += 1;
	return `attempt:test-${run}:`;
};

const counterAt = (keyPrefix: string, connection: Redis, now?: () => number): AttemptCounter =>
	createRedisAttemptCounter({
		client: makeIoredisClients(connection).attemptCounterClient,
		keyPrefix,
		...(now === undefined ? {} : { now }),
	});

/** A clock the harness moves by hand, starting at the host's time so every deadline is ahead of the server's. */
const handClock = () => {
	let now = Date.now();
	return {
		now: () => now,
		advance: (ms: number) => {
			now += ms;
		},
	};
};

const harness = (clocked: boolean) => async (): Promise<AttemptCounterHarness> => {
	const prefix = freshPrefix();
	const clock = clocked ? handClock() : undefined;
	const opened: Redis[] = [];
	return {
		counter: counterAt(prefix, first(), clock?.now),
		second: counterAt(prefix, second(), clock?.now),
		...(clock === undefined ? {} : { clock }),
		unreachable: () => {
			const io = new Redis({
				host: "127.0.0.1",
				port: 1,
				lazyConnect: true,
				enableOfflineQueue: false,
				maxRetriesPerRequest: 0,
				retryStrategy: () => null,
			});
			io.on("error", () => {});
			opened.push(io);
			return counterAt(prefix, io, clock?.now);
		},
		close: async () => {
			for (const io of opened) io.disconnect();
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
		const counter = createRedisAttemptCounter({ client: clients.attemptCounterClient });
		await counter.consume(key, SPEC);
		expect(await first().exists(`${DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX}${key}`)).toBe(1);
		expect(await first().exists(key)).toBe(0);
		await expect(clients.rateLimiterClient.incrementWithTtl(key, 60)).resolves.toBe(1);
		const next = await counter.consume(key, SPEC);
		expect([next.allowed, next.remaining]).toEqual([true, 0]);
	});

	it("expires a window's key past its end by the clock allowance, on the counter's clock", async () => {
		const prefix = freshPrefix();
		const now = Date.now() + 3_600_000;
		const counter = counterAt(prefix, first(), () => now);
		const count = await counter.consume("k", SPEC);
		expect(count.resetAt.getTime()).toBe(now + 60_000);
		expect(await first().pexpiretime(`${prefix}k`)).toBe(
			now + 60_000 + ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
		);
	});

	it("writes nothing for a refused attempt, and keeps the window's end and deadline when a later spec changes the window", async () => {
		const prefix = freshPrefix();
		const key = `${prefix}k`;
		let now = Date.now();
		const counter = counterAt(prefix, first(), () => now);
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
});

describe("createRedisAttemptCounter over a client whose reply is no count", () => {
	const SPEC: AttemptSpec = { limit: 3, windowSeconds: 60 };
	const NOW = Date.parse("2026-10-03T00:00:00.000Z");

	const answering = (reply: unknown): AttemptCounterClient => ({
		consume: async () => reply as AttemptCounterConsumeReply,
	});

	const good: AttemptCounterConsumeReply = { allowed: true, count: 1, resetAtMs: NOW + 60_000 };

	it("answers a good reply as the count it is", async () => {
		const counter = createRedisAttemptCounter({ client: answering(good), now: () => NOW });
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
		const counter = createRedisAttemptCounter({ client: answering(reply), now: () => NOW });
		await expect(counter.consume("k", SPEC)).rejects.toThrow(/createRedisAttemptCounter/);
	});

	it("rejects a clock that answers no instant, asking nothing", async () => {
		let asked = 0;
		const client: AttemptCounterClient = {
			consume: async () => {
				asked += 1;
				return good;
			},
		};
		for (const now of [Number.NaN, Number.POSITIVE_INFINITY, -1]) {
			const counter = createRedisAttemptCounter({ client, now: () => now });
			await expect(counter.consume("k", SPEC)).rejects.toThrow(RangeError);
		}
		expect(asked).toBe(0);
	});

	it("hands the client the prefixed key, the caller's clock, the limit, the window's end and the key's deadline", async () => {
		const seen: unknown[] = [];
		const client: AttemptCounterClient = {
			consume: async (key, input) => {
				seen.push([key, input]);
				return good;
			},
		};
		const counter = createRedisAttemptCounter({ client, keyPrefix: "p:", now: () => NOW + 0.7 });
		await counter.consume("login:ip:192.0.2.1", SPEC);
		expect(seen).toEqual([
			[
				"p:login:ip:192.0.2.1",
				{
					nowMs: NOW,
					limit: 3,
					resetAtMs: NOW + 60_000,
					expiresAtMs: NOW + 60_000 + ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
				},
			],
		]);
	});
});

describe("redisAttemptCounterModule", () => {
	it("has the canonical name and requires attemptCounterClient alone", () => {
		expect(redisAttemptCounterModule.name).toBe("redis-attempt-counter");
		expect(redisAttemptCounterModule.requires).toEqual(["attemptCounterClient"]);
	});

	it(`reads its own section, 'redis-attempt-counter', strict, whose keyPrefix defaults to '${DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX}'`, () => {
		const schema = redisAttemptCounterModule.section?.schema;
		expect(redisAttemptCounterModule.section?.at).toBeUndefined();
		expect(schema?.parse(undefined)).toEqual({ keyPrefix: "attempt:" });
		expect(schema?.safeParse({ keyPrefx: "a:" }).success).toBe(false);
	});

	it("fills the attemptCounter slot with a counter keyed under the section's prefix", async () => {
		const keys: string[] = [];
		const attemptCounterClient: AttemptCounterClient = {
			consume: async (key, input) => {
				keys.push(key);
				return { allowed: true, count: 1, resetAtMs: input.resetAtMs };
			},
		};
		const counter = redisAttemptCounterModule.provides?.attemptCounter?.({
			section: { keyPrefix: "tenant-a:attempt:" },
			attemptCounterClient,
		} as never) as AttemptCounter;
		await counter.consume("login:ip:192.0.2.1", { limit: 5, windowSeconds: 60 });
		expect(keys).toEqual(["tenant-a:attempt:login:ip:192.0.2.1"]);
	});
});
