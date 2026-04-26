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

import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createInMemorySingleUseTokenStore } from "./adapters/memory.mjs";
import type { SingleUseTokenStoreBase, SingleUseTokenStoreFactory } from "./types.mjs";

export function createSingleUseTokenStoreFactory(): SingleUseTokenStoreFactory {
	return createAdapterFactory<SingleUseTokenStoreBase>("SingleUseTokenStore");
}

export function registerBuiltinSingleUseTokenStores(factory: SingleUseTokenStoreFactory): void {
	factory.register("memory", () => createInMemorySingleUseTokenStore());
	factory.register("redis", async (config) => {
		const client = (config as { client?: unknown }).client;
		if (!client) {
			throw new Error(
				"singleUseTokenStore.redis: 'client' option is required. Pass a connected redis v5 client via AppOptions wiring.",
			);
		}
		const keyPrefix =
			typeof (config as { keyPrefix?: unknown }).keyPrefix === "string"
				? (config as { keyPrefix: string }).keyPrefix
				: undefined;
		const { createRedisSingleUseTokenStore } = await import("./adapters/redis.mjs");
		return createRedisSingleUseTokenStore({
			client: client as Parameters<typeof createRedisSingleUseTokenStore>[0]["client"],
			keyPrefix,
		});
	});
}

export type { SingleUseTokenStoreFactory };
