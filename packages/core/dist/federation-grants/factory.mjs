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
import { consoleLogger } from "../logging/consoleLogger.mjs";
import { createMemoryFederationGrantStore } from "./memory.mjs";
/**
 * Create an empty FederationGrantStoreFactory. Consumers register their own
 * builders, or call {@link registerBuiltinFederationGrantStores} for the
 * in-tree memory builder.
 */
export function createFederationGrantStoreFactory() {
    return createAdapterFactory("FederationGrantStore");
}
/**
 * Register the in-tree built-in builders on a FederationGrantStoreFactory.
 * Currently that is `memory` alone, which warns when it is built, as the
 * session-bound token store's does: what it holds are refresh tokens good for
 * up to a year, in the clear, gone at the next restart.
 *
 * @param logger - where the warning goes. Defaults to `consoleLogger`.
 */
export function registerBuiltinFederationGrantStores(factory, logger = consoleLogger) {
    factory.register("memory", () => {
        logger.warn("federationGrantStore: in-memory adapter is for dev/test only — do not use in production (grants and their upstream refresh tokens are held unsealed, lost on restart, and not shared between instances).");
        return createMemoryFederationGrantStore();
    });
}
