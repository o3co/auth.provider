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
 * Load `redis` and `connect-redis`, or fail naming each one that is not
 * installed and what to install — rather than with the resolver's bare
 * "Cannot find package", which says neither that the package is an optional
 * peer of this one nor which setting asked for it.
 *
 * @param imports — how each library is loaded; the default imports it.
 */
export async function loadRedisStoreLibraries(
	imports: RedisStoreLibraryImports = IMPORTS,
): Promise<RedisStoreLibraries> {
	const [redis, connectRedis] = await Promise.allSettled([imports.redis(), imports.connectRedis()]);
	const notInstalled = [
		...(redis.status === "rejected" && isNotInstalled(redis.reason, "redis")
			? [{ name: "redis", reason: redis.reason as unknown }]
			: []),
		...(connectRedis.status === "rejected" && isNotInstalled(connectRedis.reason, "connect-redis")
			? [{ name: "connect-redis", reason: connectRedis.reason as unknown }]
			: []),
	];
	if (notInstalled.length > 0) {
		const names = notInstalled.map(({ name }) => `"${name}"`).join(" and ");
		throw new Error(
			`session.storage.type is "redis", which needs "redis" and "connect-redis" — optional peer dependencies of @o3co/auth-provider-session, which it does not install — and ${names} ${notInstalled.length === 1 ? "is" : "are"} not installed. Install them beside @o3co/auth-provider-session: npm install redis connect-redis`,
			{ cause: notInstalled[0]?.reason },
		);
	}
	if (redis.status === "rejected") throw redis.reason;
	if (connectRedis.status === "rejected") throw connectRedis.reason;
	return { createClient: redis.value.createClient, RedisStore: connectRedis.value.RedisStore };
}
