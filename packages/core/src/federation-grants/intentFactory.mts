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
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { createMemoryFederationGrantIntentStore } from "./intentMemory.mjs";
import type { FederationGrantIntentStore } from "./intentStore.mjs";

/** Domain-specific AdapterFactory alias for {@link FederationGrantIntentStore} (#593, slice 6). */
export type FederationGrantIntentStoreFactory = AdapterFactory<FederationGrantIntentStore>;

/**
 * Create an empty FederationGrantIntentStoreFactory. Consumers register their
 * own builders, or call {@link registerBuiltinFederationGrantIntentStores} for
 * the in-tree memory builder.
 */
export function createFederationGrantIntentStoreFactory(): FederationGrantIntentStoreFactory {
	return createAdapterFactory<FederationGrantIntentStore>("FederationGrantIntentStore");
}

/**
 * Register the in-tree built-in builders. Currently `memory` alone, which warns
 * when it is BUILT and not when it is registered: registering is what a library
 * did, building is what a deployment did.
 *
 * @param logger - where the warning goes. Defaults to `consoleLogger`.
 */
export function registerBuiltinFederationGrantIntentStores(
	factory: FederationGrantIntentStoreFactory,
	logger: Logger = consoleLogger,
): void {
	factory.register("memory", () => {
		logger.warn(
			"federationGrantIntentStore: in-memory adapter is for dev/test only — a flow started on one instance cannot be finished on another (every callback answers as unknown), and a restart loses every connect in progress.",
		);
		return createMemoryFederationGrantIntentStore();
	});
}
