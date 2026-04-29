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
import type {
	SessionFamilyIndex,
	SessionFamilyIndexFactory,
	SessionFederationIndex,
	SessionFederationIndexFactory,
	SessionRPRegistry,
	SessionRPRegistryFactory,
	UserSessionStore,
	UserSessionStoreFactory,
} from "./types.mjs";

/**
 * AdapterFactory builders for the 4 user-session stores. Per A6+A7 §2.3:
 * register throws on duplicate, replace is the explicit override path,
 * NO freeze() lifecycle. Per A4 §5.7 + §8.4.
 *
 * The composition-root path is for consumers that select adapters by name
 * from configuration (e.g. SESSION_BACKEND=redis). The bundled module
 * (memorySessionStoresModule / redisSessionStoresModule) is the recommended
 * default — see A4 §8.1.
 */
export function createUserSessionStoreFactory(): UserSessionStoreFactory {
	return createAdapterFactory<UserSessionStore>("UserSessionStore");
}

export function createSessionRPRegistryFactory(): SessionRPRegistryFactory {
	return createAdapterFactory<SessionRPRegistry>("SessionRPRegistry");
}

export function createSessionFamilyIndexFactory(): SessionFamilyIndexFactory {
	return createAdapterFactory<SessionFamilyIndex>("SessionFamilyIndex");
}

export function createSessionFederationIndexFactory(): SessionFederationIndexFactory {
	return createAdapterFactory<SessionFederationIndex>("SessionFederationIndex");
}

export type {
	UserSessionStoreFactory,
	SessionRPRegistryFactory,
	SessionFamilyIndexFactory,
	SessionFederationIndexFactory,
};
