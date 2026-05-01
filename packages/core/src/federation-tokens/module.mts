/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { defineModule } from "../modules/index.mjs";
import { createInMemoryFederationTokenStore } from "./adapters/memory.mjs";

/**
 * In-memory FederationTokenStore module. Maps to the existing
 * `createInMemoryFederationTokenStore` adapter (plaintext, single-process).
 *
 * For production, use `redisFederationTokenStoreModule` from
 * `@o3co/auth-provider-redis`.
 *
 * Phase 10 Q5: completes the Module-pattern parity for the
 * `federationTokenStore` ComponentMap slot (added in Phase 9 Task 4).
 */
export const memoryFederationTokenStoreModule = defineModule({
	name: "core-federation-token-store-memory",
	provides: {
		federationTokenStore: () => createInMemoryFederationTokenStore(),
	},
});
