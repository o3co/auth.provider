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
import type { UserSessionStoreBase, UserSessionStoreFactory } from "./types.mjs";

export function createUserSessionStoreFactory(): UserSessionStoreFactory {
	return createAdapterFactory<UserSessionStoreBase>("userSessionStore");
}

export function registerBuiltinUserSessionStores(factory: UserSessionStoreFactory): void {
	factory.register("memory", () => createInMemoryUserSessionStore());
	factory.register("redis", async (config) => {
		const client = (config as { client?: unknown }).client;
		if (!client) {
			throw new Error(
				`userSessionStore.redis: 'client' option is required. Pass a connected 'redis' v5 client via AppOptions wiring.`,
			);
		}
		const keyPrefix =
			typeof (config as { keyPrefix?: unknown }).keyPrefix === "string"
				? (config as { keyPrefix: string }).keyPrefix
				: undefined;
		const { createRedisUserSessionStore } = await import("./adapters/redis.mjs");
		return createRedisUserSessionStore({
			client: client as Parameters<typeof createRedisUserSessionStore>[0]["client"],
			keyPrefix,
		});
	});
}

export type { UserSessionStoreFactory };
