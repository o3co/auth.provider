/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { defineModule } from "../modules/index.mjs";
import { createInMemoryFederationTokenStore } from "./adapters/memory.mjs";

/**
 * In-memory FederationTokenStore module (plaintext, single-process). For
 * production, use `redisFederationTokenStoreModule` from
 * `@o3co/auth-provider-redis`.
 */
export const memoryFederationTokenStoreModule = defineModule({
	name: "core-federation-token-store-memory",
	// What forks per replica, quoted when a multi-replica boot is refused.
	replicaSafety: {
		unsafe: true,
		reason:
			"upstream federation tokens fork per replica — a token stored on one replica is missing on the others",
	},
	provides: {
		federationTokenStore: () => createInMemoryFederationTokenStore(),
	},
});
