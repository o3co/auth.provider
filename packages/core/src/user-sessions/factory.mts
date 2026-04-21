/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createInMemoryUserSessionStore } from "./adapters/memory.mjs";
import type { UserSessionStoreBase, UserSessionStoreFactory } from "./types.mjs";

export function createUserSessionStoreFactory(): UserSessionStoreFactory & { kind: string } {
	const factory = createAdapterFactory<UserSessionStoreBase>("userSessionStore");
	return Object.assign(factory, { kind: "userSessionStore" });
}

export function registerBuiltinUserSessionStores(
	factory: UserSessionStoreFactory,
): void {
	factory.register("memory", () => createInMemoryUserSessionStore());
}

export type { UserSessionStoreFactory };
