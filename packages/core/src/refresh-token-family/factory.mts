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
import { createMemoryRefreshTokenFamilyStore } from "./adapters/memory.mjs";
import type { RefreshTokenFamilyStore } from "./types.mjs";

/**
 * Domain-specific AdapterFactory alias for RefreshTokenFamilyStore.
 *
 * Per A3 §5.6: register(type, builder) throws on duplicate; replace(type,
 * builder) is the explicit override path; NO freeze() method (composition-
 * root concern, not module registry). A6+A7 registry policy.
 */
export type RefreshTokenFamilyStoreFactory = AdapterFactory<RefreshTokenFamilyStore>;

/**
 * Create an empty RefreshTokenFamilyStoreFactory. Consumers register
 * their builders (or call registerBuiltinRefreshTokenFamilyStores for the
 * in-tree memory builder).
 */
export function createRefreshTokenFamilyStoreFactory(): RefreshTokenFamilyStoreFactory {
	return createAdapterFactory<RefreshTokenFamilyStore>("RefreshTokenFamilyStore");
}

/**
 * Register the in-tree built-in builders on a RefreshTokenFamilyStoreFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export function registerBuiltinRefreshTokenFamilyStores(
	factory: RefreshTokenFamilyStoreFactory,
): void {
	factory.register("memory", () => createMemoryRefreshTokenFamilyStore());
}
