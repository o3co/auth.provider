import { type AdapterFactory } from "@o3co/auth-provider-core";
import type session from "express-session";
/**
 * Factory for session stores. Builders may return `undefined` for adapters that
 * delegate to express-session's default in-memory store (e.g. the `"memory"` builder).
 */
export type SessionStoreFactory = AdapterFactory<session.Store | undefined>;
/**
 * Construct a fresh {@link SessionStoreFactory}. Register built-in adapters via
 * {@link registerBuiltinSessionStores} or custom adapters via `factory.register`.
 */
export declare function createSessionStoreFactory(): SessionStoreFactory;
/**
 * Register the built-in session store adapters:
 * - `"memory"` — returns `undefined`; express-session falls back to its default
 *   in-memory store.
 * - `"redis"` — constructs a `connect-redis` RedisStore backed by a `redis` client
 *   (URL + optional password). The builder uses dynamic `import(...)` so consumers
 *   that only want the memory adapter don't pay the redis load cost.
 */
export declare function registerBuiltinSessionStores(factory: SessionStoreFactory): void;
//# sourceMappingURL=factory.d.mts.map