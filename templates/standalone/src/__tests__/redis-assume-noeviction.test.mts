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
 * `redis-clients.assumeNoEviction` (`REDIS_CLIENTS_ASSUME_NO_EVICTION`), on a
 * Redis that will not report its eviction policy: every store on Redis, as a
 * multi-replica deployment selects them. ioredis is a stand-in that refuses
 * `INFO` and `CONFIG` as an ACL-restricted user's connection does; every
 * other command resolves to nothing. node-redis and connect-redis, behind
 * express-session's store, are stand-ins too, as in
 * `all-modules-composition.multi.test.mts`.
 */

import { BootError } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type Composition, compose, MULTI_ENV } from "./all-modules-composition.fixture.mjs";

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
	// express-session subscribes to store events, so the stand-in is an emitter.
	return {
		RedisStore: class MockRedisStore extends EventEmitter {
			get(): unknown {
				return undefined;
			}
			set(): void {}
			destroy(): void {}
		},
	};
});

vi.mock("ioredis", () => {
	const refused = async (): Promise<never> => {
		throw Object.assign(new Error("NOPERM this user has no permissions to run this command"), {
			name: "ReplyError",
		});
	};
	const explicit: Record<string, unknown> = {
		on: () => undefined,
		quit: async () => "OK",
		disconnect: () => undefined,
		ping: async () => "PONG",
		info: refused,
		config: refused,
	};
	const makeMockRedis = (): object =>
		new Proxy(
			{},
			{
				get(_target, prop) {
					// A function-valued `then` would make the instance a thenable.
					if (typeof prop !== "string" || prop === "then") return undefined;
					if (prop === "duplicate") return makeMockRedis;
					if (prop in explicit) return explicit[prop];
					return async () => null;
				},
			},
		);
	function MockRedis(): object {
		return makeMockRedis();
	}
	return { Redis: MockRedis, default: MockRedis };
});

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

const composing = (env: Readonly<Record<string, string>>): Promise<unknown> =>
	compose({ env, environment: "production", shippedRefreshTokenFamilyStore: true }).then(
		(composition) => {
			current = composition;
			return undefined;
		},
		(caught: unknown) => caught,
	);

describe("a Redis that will not report its eviction policy", () => {
	it.each([
		["unset", MULTI_ENV],
		["false", { ...MULTI_ENV, REDIS_CLIENTS_ASSUME_NO_EVICTION: "false" }],
	])(
		"refuses the boot with REDIS_CLIENTS_ASSUME_NO_EVICTION %s, naming the store",
		async (_label, env) => {
			const err = await composing(env);
			expect(err).toBeInstanceOf(BootError);
			expect(err).toMatchObject({
				reason: "provides-factory-failed",
				cause: { name: "RedisStoreEvictableError", maxmemoryPolicy: undefined },
			});
		},
	);

	it("boots every store with REDIS_CLIENTS_ASSUME_NO_EVICTION=true", async () => {
		expect(
			await composing({ ...MULTI_ENV, REDIS_CLIENTS_ASSUME_NO_EVICTION: "true" }),
		).toBeUndefined();
		expect(current?.modules.map((module) => module.name)).toEqual(
			expect.arrayContaining([
				"redis-attempt-counter",
				"redis-session-stores",
				"redis-federation-token-store",
			]),
		);
	});

	it("boots with redis-clients.assumeNoEviction = true written in HOCON", async () => {
		const composition = await compose({
			env: MULTI_ENV,
			environment: "production",
			shippedRefreshTokenFamilyStore: true,
			operatorHocon: "redis-clients.assumeNoEviction = true\n",
		});
		current = composition;
		expect(composition.handle).toBeDefined();
	});
});
