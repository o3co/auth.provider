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

import { type AdapterFactory, createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createMemoryConsentStore } from "./memory.mjs";
import type { ConsentStore } from "./types.mjs";

/** Domain-specific AdapterFactory alias for {@link ConsentStore} (#527). */
export type ConsentStoreFactory = AdapterFactory<ConsentStore>;

/**
 * Create an empty ConsentStoreFactory. Consumers register their own builders,
 * or call {@link registerBuiltinConsentStores} for the in-tree memory builder.
 */
export function createConsentStoreFactory(): ConsentStoreFactory {
	return createAdapterFactory<ConsentStore>("ConsentStore");
}

/**
 * Register the in-tree built-in builders on a ConsentStoreFactory. Currently
 * registers "memory". Throws AdapterFactoryError reason "duplicate" if any
 * builtin name is already registered.
 */
export function registerBuiltinConsentStores(factory: ConsentStoreFactory): void {
	factory.register("memory", () => createMemoryConsentStore());
}
