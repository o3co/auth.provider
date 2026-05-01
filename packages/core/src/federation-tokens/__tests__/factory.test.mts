/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import {
	createFederationTokenStoreFactory,
	registerBuiltinFederationTokenStores,
} from "../factory.mjs";

describe("FederationTokenStoreFactory", () => {
	it("built-in memory is registered", async () => {
		const f = createFederationTokenStoreFactory();
		registerBuiltinFederationTokenStores(f);
		const store = await f.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});

	it("does NOT register the 'redis' backend (relocated to @o3co/auth-provider-redis in Phase 10)", () => {
		const f = createFederationTokenStoreFactory();
		registerBuiltinFederationTokenStores(f);
		expect(f.registeredTypes()).not.toContain("redis");
	});
});
