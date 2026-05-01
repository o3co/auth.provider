/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import { memoryFederationTokenStoreModule } from "../module.mjs";

describe("memoryFederationTokenStoreModule", () => {
	it("has the canonical name", () => {
		expect(memoryFederationTokenStoreModule.name).toBe("core-federation-token-store-memory");
	});

	it("declares no requires (zero deps)", () => {
		expect(memoryFederationTokenStoreModule.requires ?? []).toEqual([]);
	});

	it("provides federationTokenStore", () => {
		expect(typeof memoryFederationTokenStoreModule.provides?.federationTokenStore).toBe("function");
		const store = memoryFederationTokenStoreModule.provides?.federationTokenStore?.({} as never);
		expect(store?.kind).toBe("memory");
	});
});
