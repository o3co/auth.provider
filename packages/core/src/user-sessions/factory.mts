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
import type { UserSessionStore, UserSessionStoreFactory } from "./types.mjs";

/**
 * AdapterFactory builder for the user-session store: `register`
 * throws on a duplicate, `replace` is the explicit override, and there is
 * no `freeze()`. For compositions that pick an adapter by name from
 * configuration (e.g. `SESSION_BACKEND=redis`); the bundled modules
 * (`memorySessionStoresModule`, `redisSessionStoresModule`) are the default.
 */
export function createUserSessionStoreFactory(): UserSessionStoreFactory {
	return createAdapterFactory<UserSessionStore>("UserSessionStore");
}

export type { UserSessionStoreFactory };
