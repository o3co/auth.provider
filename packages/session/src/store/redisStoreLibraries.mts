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
 * Loads the Redis session store's two libraries, `redis` and `connect-redis`,
 * which are optional peer dependencies of this package: nothing imports them
 * until the Redis store is built, so a deployment on the memory store need not
 * install them. When one is not installed, the load fails with a message that
 * names it and the install command, rather than with the resolver's bare
 * "Cannot find package". Internal to the package; `factory.mts` is its caller.
 */

/** What the Redis store builder uses from the two libraries. */
export type RedisStoreLibraries = {
	readonly createClient: typeof import("redis").createClient;
	readonly RedisStore: typeof import("connect-redis").RedisStore;
};

/** How each library is loaded: `import()` of its package name. */
export interface RedisStoreLibraryImports {
	readonly redis: () => Promise<Pick<typeof import("redis"), "createClient">>;
	readonly connectRedis: () => Promise<Pick<typeof import("connect-redis"), "RedisStore">>;
}

const IMPORTS: RedisStoreLibraryImports = {
	redis: () => import("redis"),
	connectRedis: () => import("connect-redis"),
};

/**
 * Whether `reason` is Node's resolver reporting that the package `name` itself
 * is not installed (`ERR_MODULE_NOT_FOUND`, "Cannot find package '<name>'").
 * A package that is installed but misses a dependency of its own names that
 * dependency instead, and is rethrown unchanged.
 */
function isNotInstalled(reason: unknown, name: string): boolean {
	const { code, message } = (reason ?? {}) as { code?: unknown; message?: unknown };
	return (
		code === "ERR_MODULE_NOT_FOUND" && typeof message === "string" && message.includes(`'${name}'`)
	);
}

/**
 * The install command a not-installed message gives: the peer ranges this
 * package's manifest declares, so it cannot install a major the package does
 * not support. `redisStoreLibraries.test.mts` holds it, and both READMEs, to
 * the manifest.
 */
const INSTALL_COMMAND = "npm install redis@^6.2.1 connect-redis@^10.0.0";

/**
 * How much of each member's message the AggregateError's own message quotes:
 * its first line, cut to this length. Two of them, the header and the prefix
 * createApp adds (`Module "sessionStoreModule" route factory failed:
 * AggregateError: `) fit in the 256 characters core's loggableError keeps of
 * a message.
 */
const MEMBER_BRIEF_LENGTH = 60;

const briefOf = (reason: unknown): string => {
	const [line = ""] = (reason instanceof Error ? reason.message : String(reason)).split("\n");
	return line.length > MEMBER_BRIEF_LENGTH ? `${line.slice(0, MEMBER_BRIEF_LENGTH - 1)}…` : line;
};

/**
 * Load `redis` and `connect-redis`, or fail without losing a failure:
 *
 * - A library that is not installed is named, in one message for both —
 *   rather than the resolver's bare "Cannot find package", which says neither
 *   that the package is an optional peer of this one nor which setting asked
 *   for it. The resolver's error is the cause.
 * - When the other library failed for a different reason, the message says so
 *   and that failure is the cause instead: the message already names what is
 *   missing, and the other failure is what it cannot restate.
 * - A single failure of any other kind is rethrown unchanged; two are thrown
 *   together as an `AggregateError`, whose message names each package with the
 *   first line of its failure, cut short. The members themselves are its
 *   `errors`, logged whole where core's loggableError projects them.
 *
 * What a message is for comes first: the names and the install command, then
 * the explanation. createApp prefixes the route factory's error with
 * `Module "sessionStoreModule" route factory failed: `, and a log line keeps
 * 256 characters of a message (core's LOGGED_STRING_MAX_LENGTH); the install
 * command and what failed are inside them for every combination
 * (`redisStoreLibraries.test.mts`).
 *
 * @param imports — how each library is loaded; the default imports it.
 */
export async function loadRedisStoreLibraries(
	imports: RedisStoreLibraryImports = IMPORTS,
): Promise<RedisStoreLibraries> {
	const [redis, connectRedis] = await Promise.allSettled([imports.redis(), imports.connectRedis()]);
	if (redis.status === "fulfilled" && connectRedis.status === "fulfilled") {
		return { createClient: redis.value.createClient, RedisStore: connectRedis.value.RedisStore };
	}
	const failures = [
		{ name: "redis", result: redis },
		{ name: "connect-redis", result: connectRedis },
	].flatMap(({ name, result }) =>
		result.status === "rejected"
			? [
					{
						name,
						reason: result.reason as unknown,
						notInstalled: isNotInstalled(result.reason, name),
					},
				]
			: [],
	);
	const notInstalled = failures.filter((failure) => failure.notInstalled);
	const other = failures.filter((failure) => !failure.notInstalled);

	const [firstMissing] = notInstalled;
	if (firstMissing !== undefined) {
		const names = notInstalled.map(({ name }) => `"${name}"`).join(" and ");
		const [otherFailure] = other;
		throw new Error(
			`${names} ${notInstalled.length === 1 ? "is" : "are"} not installed: run ${INSTALL_COMMAND}${otherFailure === undefined ? "" : `; "${otherFailure.name}" failed to load as well, for another reason, which is this error's cause`} (session.storage.type is "redis", and redis and connect-redis are optional peer dependencies of @o3co/auth-provider-session, which does not install them)`,
			{ cause: otherFailure === undefined ? firstMissing.reason : otherFailure.reason },
		);
	}
	if (other.length > 1) {
		throw new AggregateError(
			other.map(({ reason }) => reason),
			`${other.map(({ name }) => `"${name}"`).join(" and ")} failed to load: ${other.map(({ name, reason }) => `${name}: ${briefOf(reason)}`).join("; ")}`,
		);
	}
	throw other[0]?.reason;
}
