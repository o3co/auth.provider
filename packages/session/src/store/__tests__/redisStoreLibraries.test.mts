/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * How the Redis session store's library loader tells "this package is not
 * installed" from every other load failure, in-process.
 *
 * Each case hands the loader the rejection an `import()` produces: Node's
 * resolver errors are built here in the shape Node gives them — code and
 * message, as `optionalPeers.test.mts` observes them from the real resolver in
 * a child process. What the loader must never do is report a failure it did
 * not diagnose as a missing package, or lose one it did not report.
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { LOGGED_STRING_MAX_LENGTH, loggableError } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	loadRedisStoreLibraries,
	type RedisStoreLibraryImports,
} from "#/store/redisStoreLibraries.mjs";

const PACKAGE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

/** What Node's ESM resolver throws when `name` is not installed where `from` looks. */
function packageNotFound(name: string, from = "/app/node_modules/x/dist/index.mjs"): Error {
	return Object.assign(new Error(`Cannot find package '${name}' imported from ${from}`), {
		code: "ERR_MODULE_NOT_FOUND",
	});
}

const createClient = (() => undefined) as unknown as typeof import("redis").createClient;
class RedisStore {}

const loads =
	<T,>(value: T) =>
	() =>
		Promise.resolve(value);
const fails = (reason: unknown) => () => Promise.reject(reason);

function imports(over: Partial<Record<keyof RedisStoreLibraryImports, () => Promise<unknown>>>) {
	return {
		redis: loads({ createClient }),
		connectRedis: loads({ RedisStore }),
		...over,
	} as RedisStoreLibraryImports;
}

async function failure(over: Parameters<typeof imports>[0]): Promise<unknown> {
	try {
		await loadRedisStoreLibraries(imports(over));
	} catch (err) {
		return err;
	}
	throw new Error("the loader did not fail");
}

const manifest = JSON.parse(readFileSync(join(PACKAGE_DIR, "package.json"), "utf8")) as {
	peerDependencies: Record<string, string>;
};
const INSTALL = `npm install redis@${manifest.peerDependencies.redis} connect-redis@${manifest.peerDependencies["connect-redis"]}`;

describe("loadRedisStoreLibraries", () => {
	it("returns the two libraries when both load", async () => {
		const libraries = await loadRedisStoreLibraries(imports({}));
		expect(libraries.createClient).toBe(createClient);
		expect(libraries.RedisStore).toBe(RedisStore);
	});

	describe("a library that is not installed is named, with the install command", () => {
		it.each([
			["redis", { redis: fails(packageNotFound("redis")) }, '"redis" is not installed'],
			[
				"connect-redis",
				{ connectRedis: fails(packageNotFound("connect-redis")) },
				'"connect-redis" is not installed',
			],
			[
				"both",
				{
					redis: fails(packageNotFound("redis")),
					connectRedis: fails(packageNotFound("connect-redis")),
				},
				'"redis" and "connect-redis" are not installed',
			],
		])("missing: %s", async (_missing, over, missing) => {
			const err = (await failure(over)) as Error;
			expect(err.message.startsWith(`${missing}: run ${INSTALL} (`)).toBe(true);
			expect(err.message).toContain('session.storage.type is "redis"');
			expect(err.message).toContain(
				"optional peer dependencies of @o3co/auth-provider-session, which does not install them",
			);
		});

		it("keeps the resolver's error as the cause", async () => {
			const reason = packageNotFound("connect-redis");
			const err = (await failure({ connectRedis: fails(reason) })) as Error;
			expect(err.cause).toBe(reason);
		});
	});

	describe("any other load failure is not reported as a missing package", () => {
		it.each([
			[
				"an installed redis whose own dependency is missing",
				packageNotFound("@redis/client", "/app/node_modules/redis/dist/index.js"),
			],
			[
				"an installed redis missing its own entry file",
				Object.assign(
					new Error(
						"Cannot find module '/app/node_modules/redis/dist/index.js' imported from /app/dist/store/redisStoreLibraries.mjs",
					),
					{ code: "ERR_MODULE_NOT_FOUND" },
				),
			],
			[
				"CommonJS's MODULE_NOT_FOUND",
				Object.assign(new Error("Cannot find module 'redis'\nRequire stack:\n- /app/x.js"), {
					code: "MODULE_NOT_FOUND",
				}),
			],
			["an error thrown while the package evaluates", new TypeError("redis failed to evaluate")],
			["a rejection that is not an Error at all", null],
		])("rethrows %s unchanged", async (_case, reason) => {
			expect(await failure({ redis: fails(reason) })).toBe(reason);
		});
	});

	describe("no failure is lost when both libraries fail", () => {
		it.each([
			["redis", "connect-redis"],
			["connect-redis", "redis"],
		])(
			'names "%s" as not installed and keeps the other failure of "%s" as the cause',
			async (missing, broken) => {
				const other = new TypeError(`${broken} failed to evaluate`);
				const err = (await failure({
					[missing === "redis" ? "redis" : "connectRedis"]: fails(packageNotFound(missing)),
					[broken === "redis" ? "redis" : "connectRedis"]: fails(other),
				})) as Error;
				expect(
					err.message.startsWith(
						`"${missing}" is not installed: run ${INSTALL}; "${broken}" failed to load as well, for another reason, which is this error's cause (`,
					),
				).toBe(true);
				expect(err.cause).toBe(other);
			},
		);

		// The aggregate carries the two failures as its `errors`, whole, and says
		// in fixed text which packages they are: a failure's own text is never
		// copied into the message, where it would travel on as a plain string
		// past every projection. core's loggableError projects the members.
		const BOTH_FAILED =
			'"redis" and "connect-redis" both failed to load, for a reason other than not being installed; the two failures are this error\'s errors';

		it("throws both other failures together, in fixed text", async () => {
			const redisReason = new TypeError("redis failed to evaluate");
			const connectRedisReason = new RangeError("connect-redis failed to evaluate");
			const err = await failure({
				redis: fails(redisReason),
				connectRedis: fails(connectRedisReason),
			});
			expect(err).toBeInstanceOf(AggregateError);
			expect((err as AggregateError).errors).toEqual([redisReason, connectRedisReason]);
			expect((err as AggregateError).message).toBe(BOTH_FAILED);
		});

		it("keeps a failure that is not an Error among the errors, and out of the message", async () => {
			const err = (await failure({
				redis: fails(new TypeError("redis failed to evaluate")),
				connectRedis: fails("connect-redis threw a string"),
			})) as AggregateError;
			expect(err.errors).toEqual([expect.any(TypeError), "connect-redis threw a string"]);
			expect(err.message).toBe(BOTH_FAILED);
		});
	});

	// What a log line keeps of the boot failure. createApp wraps what the route
	// factory threw as `Module "<name>" route factory failed: ${String(err)}`
	// (core's boot/apply-contributions.mts), and core's loggableError keeps the
	// first LOGGED_STRING_MAX_LENGTH characters of a message. The install
	// command, and what failed, have to be inside them.
	describe("a log line keeps what the message is for", () => {
		const logged = (err: unknown) =>
			`Module "sessionStoreModule" route factory failed: ${String(err)}`.slice(
				0,
				LOGGED_STRING_MAX_LENGTH,
			);
		const evaluationError = (name: string) =>
			new TypeError(`${name} failed to evaluate: ${"a long reason, ".repeat(20)}`);

		it.each([
			["redis missing", { redis: fails(packageNotFound("redis")) }, ['"redis"']],
			[
				"connect-redis missing",
				{ connectRedis: fails(packageNotFound("connect-redis")) },
				['"connect-redis"'],
			],
			[
				"both missing",
				{
					redis: fails(packageNotFound("redis")),
					connectRedis: fails(packageNotFound("connect-redis")),
				},
				['"redis" and "connect-redis"'],
			],
			[
				"redis missing, connect-redis broken",
				{
					redis: fails(packageNotFound("redis")),
					connectRedis: fails(evaluationError("connect-redis")),
				},
				['"redis"', '"connect-redis" failed to load as well'],
			],
			[
				"connect-redis missing, redis broken",
				{
					redis: fails(evaluationError("redis")),
					connectRedis: fails(packageNotFound("connect-redis")),
				},
				['"connect-redis"', '"redis" failed to load as well'],
			],
		])("%s: the install command and what failed", async (_case, over, named) => {
			const line = logged(await failure(over));
			expect(line).toContain(INSTALL);
			for (const text of named) expect(line).toContain(text);
		});

		it("both broken: the line names both packages, and the projection carries each failure", async () => {
			const redisReason = evaluationError("redis");
			const connectRedisReason = evaluationError("connect-redis");
			const err = await failure({
				redis: fails(redisReason),
				connectRedis: fails(connectRedisReason),
			});
			const line = logged(err);
			expect(line).toContain('"redis" and "connect-redis" both failed to load');
			// What core's loggableError writes for the aggregate: each member,
			// projected, as `aggregateErrors`.
			expect(loggableError(err)).toMatchObject({
				name: "AggregateError",
				aggregateErrors: [
					{ name: "TypeError", detail: expect.stringContaining("redis failed to evaluate") },
					{
						name: "TypeError",
						detail: expect.stringContaining("connect-redis failed to evaluate"),
					},
				],
			});
		});
	});

	it("gives the peer ranges of the manifest in the install command, as both READMEs do", () => {
		expect(INSTALL).toMatch(/^npm install redis@\S+ connect-redis@\S+$/);
		for (const readme of ["README.md", "README.ja.md"]) {
			const text = readFileSync(join(PACKAGE_DIR, readme), "utf8");
			expect(text, readme).toContain(INSTALL);
			expect(text, readme).not.toMatch(/npm install redis connect-redis/);
		}
	});
});
