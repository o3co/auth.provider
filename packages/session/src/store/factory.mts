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
import {
	type AdapterFactory,
	type BuilderContext,
	consoleLogger,
	createAdapterFactory,
	loggableError,
} from "@o3co/auth-provider-core";
import type session from "express-session";

/**
 * Factory for session stores. Builders may return `undefined` for adapters that
 * delegate to express-session's default in-memory store (e.g. the `"memory"` builder).
 */
export type SessionStoreFactory = AdapterFactory<session.Store | undefined>;

/**
 * Construct a fresh {@link SessionStoreFactory}. Register built-in adapters via
 * {@link registerBuiltinSessionStores} or custom adapters via `factory.register`.
 *
 * @param ctx — optional `BuilderContext`. When supplied, built-in builders that
 *   create disposable sub-resources (the redis builder's underlying client)
 *   register their cleanup via `ctx.lifecycle?.register(...)` so
 *   `AppHandle.dispose()` drains them.
 */
export function createSessionStoreFactory(ctx?: BuilderContext): SessionStoreFactory {
	return createAdapterFactory<session.Store | undefined>("SessionStore", ctx ?? {});
}

/**
 * The Redis store's two libraries. They are optional peer dependencies of this
 * package, so a deployment on the memory store installs neither and nothing
 * here imports them until the Redis store is built.
 */
type RedisStoreLibraries = {
	readonly createClient: typeof import("redis").createClient;
	readonly RedisStore: typeof import("connect-redis").RedisStore;
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
 */
async function loadRedisStoreLibraries(): Promise<RedisStoreLibraries> {
	const [redis, connectRedis] = await Promise.allSettled([
		import("redis"),
		import("connect-redis"),
	]);
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

/**
 * Register the built-in session store adapters:
 * - `"memory"` — returns `undefined`; express-session falls back to its default
 *   in-memory store.
 * - `"redis"` — constructs a `connect-redis` RedisStore backed by a `redis` client
 *   (URL + optional password). The two libraries are optional peer
 *   dependencies of this package: the builder loads them with `import(...)`
 *   when it runs, so a deployment on the memory adapter need not install
 *   them, and one on this adapter that did not fails with an error naming the
 *   missing package and the install command.
 *
 * The redis builder forwards the BuilderContext supplied at adapter-create time
 * (via `createSessionStoreFactory(ctx)`) so it can register `client.quit()` on
 * the lifecycle registrar — closes OR-M2.
 *
 * The redis client's `error` events are reported through
 * `BuilderContext.logger` — the same context that carries `lifecycle` and
 * `readiness` — falling back to `consoleLogger` when the composition wires no
 * logger slot.
 */
export function registerBuiltinSessionStores(factory: SessionStoreFactory): void {
	factory.register("memory", () => undefined);

	factory.register("redis", async (config, ctx) => {
		const { url, password } = config as { url?: unknown; password?: unknown };
		if (typeof url !== "string" || url.length === 0) {
			throw new Error('redis session store requires "url" in config');
		}
		const { createClient, RedisStore } = await loadRedisStoreLibraries();
		const client = createClient({
			url,
			password: typeof password === "string" ? password : undefined,
		});

		// node-redis emits `error` on socket failures — including while it is
		// happily auto-reconnecting — and an EventEmitter `error` with no
		// listener throws, taking the whole process down. Since
		// `session.storage.type = "redis"` is the shipped default, a Redis
		// failover blip crashed the provider, and the restart reconnected into
		// the same flapping Redis: a crash loop of the identity provider.
		//
		// Attached BEFORE connect(): a connection that fails during the
		// handshake emits while connect() is still in flight, which is exactly
		// the boot-time flap this guards against. Reconnection is node-redis's
		// job; the handler's job is to make the event observed rather than
		// fatal, and to leave a trace an operator can correlate with.
		const logger = ctx.logger ?? consoleLogger;
		client.on("error", (err: unknown) => {
			logger.error({ err: loggableError(err) }, "session_store_redis_error");
		});

		await client.connect();
		// D-5 / OR-M2: register quit() with the lifecycle registrar so the
		// connect-redis client is released during AppHandle.dispose().
		ctx.lifecycle?.register(async () => {
			await client.quit();
		});
		// Sessions are load-bearing for every logged-in request, so a replica
		// that has lost this connection should stop receiving traffic. The
		// client is not reachable from the returned RedisStore, so registering
		// the probe here is the only place it can be done.
		ctx.readiness?.register({
			name: "session-store",
			check: () => client.ping(),
		});
		return new RedisStore({ client });
	});
}
