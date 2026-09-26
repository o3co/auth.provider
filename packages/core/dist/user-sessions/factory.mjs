/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createInMemoryUserSessionStore } from "./adapters/memory.mjs";
export function createUserSessionStoreFactory() {
    return createAdapterFactory("UserSessionStore");
}
export function registerBuiltinUserSessionStores(factory) {
    factory.register("memory", () => createInMemoryUserSessionStore());
    factory.register("redis", async (config) => {
        const client = config.client;
        if (!client) {
            throw new Error(`userSessionStore.redis: 'client' option is required. Pass a connected 'redis' v5 client via AppOptions wiring.`);
        }
        const keyPrefix = typeof config.keyPrefix === "string"
            ? config.keyPrefix
            : undefined;
        const { createRedisUserSessionStore } = await import("./adapters/redis.mjs");
        return createRedisUserSessionStore({
            client: client,
            keyPrefix,
        });
    });
}
