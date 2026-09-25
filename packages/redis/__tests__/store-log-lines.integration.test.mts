/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * What the Redis stores that log write, against a real Redis, when they are
 * built the way a composition builds them: by their module, with the
 * `logger` the composition fills.
 *
 * Every line is object-first, under a snake_case event name, with the
 * projection of the error behind it as `err`. Before, the session-store and
 * code-repository modules never handed their store the logger slot, so the
 * user-session store and the RP registry wrote nothing at all and the code
 * repository wrote to `consoleLogger` — and the lines they wrote were named
 * in prose ("RedisCodeRepository: corrupted data for code",
 * "user_session_corrupt_envelope: JSON.parse failed").
 */

import { randomUUID } from "node:crypto";
import type { Logger } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { redisCodeRepositoryModule } from "#/code-repository.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { redisSessionStoresModule } from "#/modules/redisSessionStores.mjs";
import { createRedisUserSessionStore } from "#/userSessionStore.mjs";
import { testRedis } from "./support/redis.mjs";

let raw: Redis;

beforeAll(async () => {
	raw = new Redis(await testRedis());
});

afterAll(async () => {
	raw?.disconnect();
});

afterEach(() => {
	vi.restoreAllMocks();
});

const FRAMES = expect.stringMatching(/^ {4}at /);

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

/** A SyntaxError's projection: its name and its frames — never the text it quotes. */
const SYNTAX_ERROR = { name: "SyntaxError", stack: FRAMES };

/** `module.provides[slot]`, called with `deps` the way the boot planner calls it. */
const provide = <T,>(
	module: { provides?: Record<string, unknown> },
	slot: string,
	deps: Record<string, unknown>,
): T => (module.provides?.[slot] as (deps: unknown) => T)(deps);

describe("redisSessionStoresModule: the stores it builds log on the composition's logger", () => {
	const sessionDeps = (keyPrefix: string, logger?: Logger) => ({
		...makeIoredisClients(raw),
		config: { redisSessionStores: { keyPrefix } },
		...(logger !== undefined ? { logger } : {}),
	});

	it("the user-session store: user_session_corrupt_envelope, object-first, the parser's projection as err", async () => {
		const keyPrefix = `store-log:ss:${randomUUID()}:`;
		const { logger, calls } = recordingLogger();
		const store = provide<{ get(sid: string): Promise<unknown> }>(
			redisSessionStoresModule,
			"userSessionStore",
			sessionDeps(keyPrefix, logger),
		);
		await raw.set(`${keyPrefix}us:sid-1`, `{"sid":"sid-1","claims":{"email":alice@example.com}}`);

		expect(await store.get("sid-1")).toBeNull();
		expect(calls).toEqual([
			{
				level: "warn",
				args: [
					{ sid: "sid-1", reason: "json_parse", err: SYNTAX_ERROR },
					"user_session_corrupt_envelope",
				],
			},
		]);
		expect(JSON.stringify(calls)).not.toContain("alice@");
	});

	it("an envelope of the wrong shape: the same event, reason shape_invalid", async () => {
		const keyPrefix = `store-log:ss:${randomUUID()}:`;
		const { logger, calls } = recordingLogger();
		const store = provide<{ get(sid: string): Promise<unknown> }>(
			redisSessionStoresModule,
			"userSessionStore",
			sessionDeps(keyPrefix, logger),
		);
		await raw.set(`${keyPrefix}us:sid-1`, `{"sid":"sid-1"}`);

		expect(await store.get("sid-1")).toBeNull();
		expect(calls).toEqual([
			{
				level: "warn",
				args: [{ sid: "sid-1", reason: "shape_invalid" }, "user_session_corrupt_envelope"],
			},
		]);
	});

	it("the RP registry: session_rp_registry_corrupt_envelope, the same shape", async () => {
		const keyPrefix = `store-log:ss:${randomUUID()}:`;
		const { logger, calls } = recordingLogger();
		const registry = provide<{ listRPs(sid: string): Promise<unknown[]> }>(
			redisSessionStoresModule,
			"sessionRPRegistry",
			sessionDeps(keyPrefix, logger),
		);
		await raw.hset(
			`${keyPrefix}rp:sid-1`,
			"rp-1",
			`{"clientId":"rp-1","backchannelLogoutUri":https://rp.example/bc}`,
		);

		expect(await registry.listRPs("sid-1")).toEqual([]);
		expect(calls).toEqual([
			{
				level: "warn",
				args: [
					{ sid: "sid-1", reason: "json_parse", err: SYNTAX_ERROR },
					"session_rp_registry_corrupt_envelope",
				],
			},
		]);
	});

	it("with no logger slot filled, consoleLogger writes the same line — never nothing", async () => {
		const keyPrefix = `store-log:ss:${randomUUID()}:`;
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const store = provide<{ get(sid: string): Promise<unknown> }>(
			redisSessionStoresModule,
			"userSessionStore",
			sessionDeps(keyPrefix),
		);
		await raw.set(`${keyPrefix}us:sid-1`, `{"sid":"sid-1"}`);

		expect(await store.get("sid-1")).toBeNull();
		expect(warn.mock.calls).toEqual([
			[{ sid: "sid-1", reason: "shape_invalid" }, "user_session_corrupt_envelope"],
		]);
	});

	it("a store built directly with no logger writes through consoleLogger too", async () => {
		const keyPrefix = `store-log:us:${randomUUID()}:`;
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const store = createRedisUserSessionStore({
			client: makeIoredisClients(raw).userSessionStoreClient,
			keyPrefix,
		});
		await raw.set(`${keyPrefix}sid-1`, `{"sid":"sid-1"}`);

		expect(await store.get("sid-1")).toBeNull();
		expect(warn).toHaveBeenCalledTimes(1);
	});
});

describe("redisCodeRepositoryModule: the repository it builds logs on the composition's logger", () => {
	/** RFC 6749 §4.1.2's example authorization code. */
	const CODE = "SplxlOBeZQQYbYS6WxSbIA";

	const repository = (keyPrefix: string, logger: Logger) =>
		provide<{ findByCode(code: string): Promise<unknown> }>(
			redisCodeRepositoryModule,
			"codeRepository",
			{
				codeRepositoryClient: makeIoredisClients(raw).codeRepositoryClient,
				config: { redisCodeRepository: { keyPrefix } },
				logger,
			},
		);

	it("a record that does not parse: authorization_code_corrupt_record, reason json_parse, the projection as err", async () => {
		const keyPrefix = `store-log:code:${randomUUID()}:`;
		const { logger, calls } = recordingLogger();
		await raw.set(`${keyPrefix}${CODE}`, `{"code":${CODE},"client_id":"rp"}`);

		expect(await repository(keyPrefix, logger).findByCode(CODE)).toBeNull();
		expect(calls).toEqual([
			{
				level: "error",
				args: [
					{ codeHash: expect.any(String), reason: "json_parse", err: SYNTAX_ERROR },
					"authorization_code_corrupt_record",
				],
			},
		]);
		expect(JSON.stringify(calls)).not.toContain(CODE.slice(0, 10));
	});

	it("a record without the identity fields: the same event, reason identity_fields_missing", async () => {
		const keyPrefix = `store-log:code:${randomUUID()}:`;
		const { logger, calls } = recordingLogger();
		await raw.set(`${keyPrefix}${CODE}`, JSON.stringify({ code_challenge: "x" }));

		expect(await repository(keyPrefix, logger).findByCode(CODE)).toBeNull();
		expect(calls).toEqual([
			{
				level: "error",
				args: [
					{ codeHash: expect.any(String), reason: "identity_fields_missing" },
					"authorization_code_corrupt_record",
				],
			},
		]);
	});
});
