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
 * What the Redis adapters write to a log when a stored value cannot be read
 * back, against a real Redis.
 *
 * A value read back from Redis is data this process stored, and a JSON
 * parser quotes the text it could not parse in its message. So a log line
 * carries core's `loggableError` projection of the error, never the error:
 * the logger here serialises every own property of what it is handed, as a
 * deployment's logger may.
 */

import { randomUUID } from "node:crypto";
import type { Logger } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RedisCodeRepository } from "#/code-repository.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";

let container: StartedTestContainer;
let raw: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 90_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

/** A logged projection's `stack`: frames only, from the first. */
const FRAMES = expect.stringMatching(/^ {4}at /);

/**
 * A logger that serialises every own property of what it is handed, `cause`
 * and non-enumerable fields included — a deployment is free to install one.
 * `lines` is what it wrote; `calls` what it was handed.
 */
function serialiseEverythingLogger(): {
	logger: Logger;
	lines: string[];
	calls: Array<{ level: string; args: unknown[] }>;
} {
	const lines: string[] = [];
	const calls: Array<{ level: string; args: unknown[] }> = [];
	const walk = (value: unknown, seen = new WeakSet<object>()): unknown => {
		if (typeof value !== "object" || value === null) return value;
		if (seen.has(value)) return "[circular]";
		seen.add(value);
		const out: Record<string, unknown> = {};
		for (const key of Object.getOwnPropertyNames(value)) {
			out[key] = walk((value as Record<string, unknown>)[key], seen);
		}
		return out;
	};
	const record =
		(level: string) =>
		(...args: unknown[]): void => {
			calls.push({ level, args });
			lines.push(JSON.stringify({ level, args: walk(args) }));
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
	return { logger, lines, calls };
}

/** What `JSON.parse` says of `text`. */
const parseMessageOf = (text: string): string => {
	try {
		JSON.parse(text);
	} catch (err) {
		return (err as Error).message;
	}
	throw new Error("parsed");
};

describe("RedisCodeRepository: a stored record it cannot parse", () => {
	/** RFC 6749 §4.1.2's example authorization code. */
	const CODE = "SplxlOBeZQQYbYS6WxSbIA";

	it.each([
		["consumeByCode", (repo: RedisCodeRepository) => repo.consumeByCode(CODE)],
		["findByCode", (repo: RedisCodeRepository) => repo.findByCode(CODE)],
	] as const)(
		"is logged by %s as a SyntaxError's projection, never the text V8 quotes from the record",
		async (_label, read) => {
			const keyPrefix = `logged-errors:code:${randomUUID()}:`;
			const { codeRepositoryClient } = makeIoredisClients(raw);
			const { logger, lines, calls } = serialiseEverythingLogger();
			const repo = new RedisCodeRepository(codeRepositoryClient, { keyPrefix, logger });
			// A record a foreign or broken writer left behind, holding a code
			// value outside a string: V8's message quotes the text around it.
			const record = `{"code":${CODE},"client_id":"rp","redirect_uri":"https://rp.example/cb"}`;
			await raw.set(`${keyPrefix}${CODE}`, record);
			const quoted = parseMessageOf(record);
			expect(quoted).toContain(CODE.slice(0, 10));

			expect(await read(repo)).toBeNull();

			expect(calls).toEqual([
				{
					level: "error",
					args: [
						{ err: { name: "SyntaxError", stack: FRAMES }, codeHash: expect.any(String) },
						"RedisCodeRepository: corrupted data for code",
					],
				},
			]);
			for (const line of lines) {
				expect(line).not.toContain(CODE.slice(0, 10));
				expect(line).not.toContain(quoted);
			}
		},
	);
});
