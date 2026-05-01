/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createInMemoryFederationTokenStore } from "./adapters/memory.mjs";
import type { FederationTokenStoreBase, FederationTokenStoreFactory } from "./types.mjs";

export function createFederationTokenStoreFactory(): FederationTokenStoreFactory {
	return createAdapterFactory<FederationTokenStoreBase>("FederationTokenStore");
}

/**
 * Registers the built-in in-memory FederationTokenStore. The "redis" backend
 * was relocated to `@o3co/auth-provider-redis` in Phase 10; consumers wire
 * it via:
 *
 *   import { redisFederationTokenStoreBuilder } from "@o3co/auth-provider-redis";
 *   factory.register("redis", redisFederationTokenStoreBuilder);
 *
 * Or use the declarative `redisFederationTokenStoreModule` in their `modules`
 * array.
 */
export function registerBuiltinFederationTokenStores(factory: FederationTokenStoreFactory): void {
	factory.register("memory", () => {
		// eslint-disable-next-line no-console
		console.warn(
			"federationTokenStore: in-memory adapter is for dev/test only — do not use in production (tokens are lost on restart, no cross-instance replication).",
		);
		return createInMemoryFederationTokenStore();
	});
}

export type { FederationTokenStoreFactory };
