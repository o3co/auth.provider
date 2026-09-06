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
import { createAdapterFactory } from "@o3co/auth-provider-core";
/**
 * Construct a fresh {@link SessionStoreFactory}. Register built-in adapters via
 * {@link registerBuiltinSessionStores} or custom adapters via `factory.register`.
 */
export function createSessionStoreFactory() {
    return createAdapterFactory("SessionStore");
}
/**
 * Register the built-in session store adapters:
 * - `"memory"` — returns `undefined`; express-session falls back to its default
 *   in-memory store.
 * - `"redis"` — constructs a `connect-redis` RedisStore backed by a `redis` client
 *   (URL + optional password). The builder uses dynamic `import(...)` so consumers
 *   that only want the memory adapter don't pay the redis load cost.
 */
export function registerBuiltinSessionStores(factory) {
    factory.register("memory", () => undefined);
    factory.register("redis", async (config) => {
        const { url, password } = config;
        if (typeof url !== "string" || url.length === 0) {
            throw new Error('redis session store requires "url" in config');
        }
        const [{ createClient }, { RedisStore }] = await Promise.all([
            import("redis"),
            import("connect-redis"),
        ]);
        const client = createClient({
            url,
            password: typeof password === "string" ? password : undefined,
        });
        await client.connect();
        return new RedisStore({ client });
    });
}
