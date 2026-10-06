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
import {
	type Composition,
	compose,
	MULTI_ENV,
	SINGLE_ENV,
} from "./all-modules-composition.fixture.mjs";

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

/** MFA required, both MFA stores on Redis, a key of the deployment's own and an SMTP relay. */
const MFA_ON_REDIS: Readonly<Record<string, string>> = {
	MFA_MODE: "required",
	ADAPTERS_MFA_FACTOR_STORE: "redis",
	ADAPTERS_MFA_TRANSACTION_STORE: "redis",
	REDIS_CLIENTS_URL: "redis://redis.test:6379",
	MFA_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString("base64"),
	STANDARD_SMTP_MAIL_SENDER_HOST: "smtp.auth.test",
	STANDARD_SMTP_MAIL_SENDER_FROM: "auth@auth.test",
};

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

describe("the MFA stores on a Redis that will not report its eviction policy", () => {
	/** Only the MFA stores on Redis: a refusal can come from no other store. */
	const MFA_ONLY = { ...SINGLE_ENV, ...MFA_ON_REDIS };

	it.each([
		["unset", MFA_ONLY],
		["false", { ...MFA_ONLY, REDIS_CLIENTS_ASSUME_NO_EVICTION: "false" }],
	])(
		"refuses the boot with REDIS_CLIENTS_ASSUME_NO_EVICTION %s, naming an MFA store",
		async (_label, env) => {
			const err = await composing(env);
			expect(err).toBeInstanceOf(BootError);
			expect(err).toMatchObject({
				reason: "provides-factory-failed",
				cause: {
					name: "RedisStoreEvictableError",
					reason: expect.stringMatching(/^mfa-(factor|transaction)-store-evictable$/),
					maxmemoryPolicy: undefined,
				},
			});
		},
	);

	it("boots both MFA stores with REDIS_CLIENTS_ASSUME_NO_EVICTION=true", async () => {
		expect(
			await composing({ ...MFA_ONLY, REDIS_CLIENTS_ASSUME_NO_EVICTION: "true" }),
		).toBeUndefined();
		expect(current?.modules.map((module) => module.name)).toEqual(
			expect.arrayContaining(["redis-mfa-factor-store", "redis-mfa-transaction-store"]),
		);
		expect(current?.handle.components.mfaFactorStore?.kind).toBe("redis");
		expect(current?.handle.components.mfaTransactionStore?.kind).toBe("redis");
	});

	it.each([
		["unset", { ...MULTI_ENV, ...MFA_ON_REDIS }],
		["false", { ...MULTI_ENV, ...MFA_ON_REDIS, REDIS_CLIENTS_ASSUME_NO_EVICTION: "false" }],
	])(
		"refuses every store on Redis with MFA on, REDIS_CLIENTS_ASSUME_NO_EVICTION %s",
		async (_label, env) => {
			expect(await composing(env)).toMatchObject({
				reason: "provides-factory-failed",
				cause: { name: "RedisStoreEvictableError", maxmemoryPolicy: undefined },
			});
		},
	);

	it("boots every store on Redis with MFA on and REDIS_CLIENTS_ASSUME_NO_EVICTION=true", async () => {
		expect(
			await composing({ ...MULTI_ENV, ...MFA_ON_REDIS, REDIS_CLIENTS_ASSUME_NO_EVICTION: "true" }),
		).toBeUndefined();
		expect(current?.handle.components.mfaFactorStore?.kind).toBe("redis");
		expect(current?.handle.components.mfaTransactionStore?.kind).toBe("redis");
	});
});
