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
	type Logger,
	loggableError,
} from "@o3co/auth-provider-core";
import type session from "express-session";
import { loadRedisStoreLibraries } from "./redisStoreLibraries.mjs";

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
 * How the Redis store reads and writes a session record: JSON, as
 * connect-redis's default does — except that a record which cannot be read is
 * absent rather than an error. Text that is not JSON, or JSON that is not a
 * session record (an object carrying a `cookie` object, which express-session
 * rebuilds the session's cookie from), would otherwise fail every request
 * that browser makes until the record expires, answered as a store outage
 * (`../internal/cookieSession.mts`). Read as absent, express-session starts a
 * fresh session for the request. Logged once per read as a warn,
 * `session_cookie_record_unreadable` with `store: "cookie_session"` — never
 * the record's text, nor the parser's message, which quotes it.
 *
 * The record is not deleted, and the browser keeps its cookie: a fresh,
 * unmodified session sets no new one (`saveUninitialized: false`). So every
 * request from that browser reads the same record again and logs another
 * warn, until the user signs in — which sets a new cookie — or the record's
 * TTL passes. A stream of these from one browser is one record.
 *
 * Every record in the store is read through this, not only sessions: a
 * `form_post` federation transaction (`fedtx:`) that cannot be read is absent,
 * so its callback answers `400 invalid_session` and the user starts the
 * federation again; an oauth re-authentication ask (`reauth:`) that cannot be
 * read is no ask, so `/authorize` asks for the re-authentication again. Both
 * warn the same way, as `store: "cookie_session"`.
 *
 * A store that cannot answer at all is not a record and never reaches here:
 * it is still the `503`.
 */
function readableSessionRecords(logger: Pick<Logger, "warn">): {
	parse(text: string): session.SessionData;
	stringify(record: session.SessionData): string;
} {
	return {
		stringify: (record) => JSON.stringify(record),
		parse: (text) => {
			let record: unknown;
			try {
				record = JSON.parse(text);
			} catch {
				record = undefined;
			}
			const cookie =
				record !== null && typeof record === "object"
					? (record as { cookie?: unknown }).cookie
					: undefined;
			if (cookie !== null && typeof cookie === "object") return record as session.SessionData;
			logger.warn({ store: "cookie_session" }, "session_cookie_record_unreadable");
			// connect-redis hands this to express-session as the stored session;
			// `null` is its "no such session".
			return null as unknown as session.SessionData;
		},
	};
}

/**
 * Register the built-in session store adapters:
 * - `"memory"` — returns `undefined`; express-session falls back to its default
 *   in-memory store.
 * - `"redis"` — constructs a `connect-redis` RedisStore backed by a `redis` client
 *   (URL + optional password). The two libraries are optional peer
 *   dependencies of this package: the builder loads them when it runs
 *   (`redisStoreLibraries.mts`), so a deployment on the memory adapter need
 *   not install them, and one on this adapter that did not fails with an
 *   error naming the missing package and the install command.
 *
 * The redis builder forwards the BuilderContext supplied at adapter-create time
 * (via `createSessionStoreFactory(ctx)`) so it can register `client.quit()` on
 * the lifecycle registrar — closes OR-M2.
 *
 * The redis client's `error` events are reported through
 * `BuilderContext.logger` — the same context that carries `lifecycle` and
 * `readiness` — falling back to `consoleLogger` when the composition wires no
 * logger slot. So is a stored record the store cannot read, which
 * {@link readableSessionRecords} reads as absent.
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
		return new RedisStore({ client, serializer: readableSessionRecords(logger) });
	});
}
