/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { createInMemoryFederationTokenStore } from "./adapters/memory.mjs";
import type { FederationTokenStore, FederationTokenStoreFactory } from "./types.mjs";

export function createFederationTokenStoreFactory(): FederationTokenStoreFactory {
	return createAdapterFactory<FederationTokenStore>("FederationTokenStore");
}

/**
 * Registers the built-in in-memory FederationTokenStore. The "redis" backend
 * is in `@o3co/auth-provider-redis`: register its
 * `redisFederationTokenStoreBuilder` as "redis", or add
 * `redisFederationTokenStoreModule` to `modules`.
 *
 * @param factory - the FederationTokenStore factory to populate.
 * @param logger - receives the dev/test warning when the builder runs.
 *                 Defaults to `consoleLogger`.
 */
export function registerBuiltinFederationTokenStores(
	factory: FederationTokenStoreFactory,
	logger: Logger = consoleLogger,
): void {
	factory.register("memory", () => {
		logger.warn(
			"federationTokenStore: in-memory adapter is for dev/test only — do not use in production (tokens are lost on restart, no cross-instance replication).",
		);
		return createInMemoryFederationTokenStore();
	});
}

export type { FederationTokenStoreFactory };
