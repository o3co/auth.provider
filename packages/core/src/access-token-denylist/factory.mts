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
import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createMemoryAccessTokenDenylist } from "./memory.mjs";
import type { AccessTokenDenylist } from "./types.mjs";

/**
 * Domain-specific AdapterFactory alias for AccessTokenDenylist.
 * Relocated from types.mts to factory.mts per sibling pattern
 * (ChallengeStore / ReplaySeenSet / RefreshTokenFamilyStore).
 */
export type AccessTokenDenylistFactory = AdapterFactory<AccessTokenDenylist>;

/**
 * Create an empty AccessTokenDenylistFactory. Consumers register their own
 * builders, or call registerBuiltinAccessTokenDenylists for the in-tree memory
 * builder.
 */
export function createAccessTokenDenylistFactory(): AccessTokenDenylistFactory {
	return createAdapterFactory<AccessTokenDenylist>("AccessTokenDenylist");
}

/**
 * Register the in-tree built-in builders on an AccessTokenDenylistFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export function registerBuiltinAccessTokenDenylists(factory: AccessTokenDenylistFactory): void {
	factory.register("memory", () => createMemoryAccessTokenDenylist());
}
