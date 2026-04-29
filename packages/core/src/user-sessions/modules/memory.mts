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

import { defineModule } from "../../modules/manifest/define-module.mjs";
import { createInMemorySessionFamilyIndex } from "../memory/sessionFamilyIndex.mjs";
import { createInMemorySessionFederationIndex } from "../memory/sessionFederationIndex.mjs";
import { createInMemorySessionRPRegistry } from "../memory/sessionRPRegistry.mjs";
import { createInMemoryUserSessionStore } from "../memory/userSessionStore.mjs";

/**
 * Bundled module providing all 4 in-memory user-session stores. Single-decision
 * wiring for the common case (Codex Q4 finding). Per A4 §8.1 + §8.2.
 *
 * For mixed wiring (e.g. memory userSessionStore + redis indexes), use
 * `overrideComponents` per A4 §8.3 — `provides[K]` is skipped when an
 * override is supplied for K.
 */
export const memorySessionStoresModule = defineModule({
	name: "memorySessionStores",
	provides: {
		userSessionStore: () => createInMemoryUserSessionStore(),
		sessionRPRegistry: () => createInMemorySessionRPRegistry(),
		sessionFamilyIndex: () => createInMemorySessionFamilyIndex(),
		sessionFederationIndex: () => createInMemorySessionFederationIndex(),
	} as never,
});
