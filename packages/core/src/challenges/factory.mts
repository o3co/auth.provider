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
import { createMemoryChallengeStore } from "./adapters/memory.mjs";
import type { ChallengeStore } from "./types.mjs";

/**
 * Domain-specific AdapterFactory alias for ChallengeStore.
 *
 * Per A1 §5.6: register(type, builder) throws on duplicate; replace(type,
 * builder) is the explicit override path; NO freeze() method (composition-
 * root concern, not module registry).
 */
export type ChallengeStoreFactory = AdapterFactory<ChallengeStore>;

/**
 * Create an empty ChallengeStoreFactory. Consumers register their builders
 * (or call registerBuiltinChallengeStores for the in-tree memory builder).
 */
export function createChallengeStoreFactory(): ChallengeStoreFactory {
	return createAdapterFactory<ChallengeStore>("challenge-store");
}

/**
 * Register the in-tree built-in builders on a ChallengeStoreFactory.
 * Currently registers "memory". Throws AdapterFactoryError reason "duplicate"
 * if any builtin name is already registered.
 */
export function registerBuiltinChallengeStores(factory: ChallengeStoreFactory): void {
	factory.register("memory", () => createMemoryChallengeStore());
}
