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

/**
 * The adapter factories of the two MFA stores, for a composition root that
 * builds a store by name rather than by installing a module.
 */

import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { MfaFactorStore, MfaFactorStoreFactory } from "./factorStore.mjs";
import { createMemoryMfaFactorStore } from "./memoryFactorStore.mjs";

/**
 * Says, once per store built, that an in-process factor store forgets every
 * enrollment at the next restart. Object-first, at warn: it is a deployment
 * choice, not an outage. Shared with `memoryMfaFactorStoreModule`; not on the
 * barrel.
 * @internal
 */
export function warnMfaFactorStoreInMemory(logger: Logger): void {
	logger.warn({ store: "mfaFactorStore", adapter: "memory" }, "mfa_factor_store_in_memory");
}

/** An empty {@link MfaFactorStoreFactory}; register builders, or call {@link registerBuiltinMfaFactorStores}. */
export function createMfaFactorStoreFactory(): MfaFactorStoreFactory {
	return createAdapterFactory<MfaFactorStore>("MfaFactorStore");
}

/**
 * Registers the in-tree builders: `memory`, which warns when it is built.
 * Throws `AdapterFactoryError` (`duplicate`) when one is already registered.
 *
 * @param logger - where the warning goes. Defaults to `consoleLogger`.
 */
export function registerBuiltinMfaFactorStores(
	factory: MfaFactorStoreFactory,
	logger: Logger = consoleLogger,
): void {
	factory.register("memory", () => {
		warnMfaFactorStoreInMemory(logger);
		return createMemoryMfaFactorStore();
	});
}
