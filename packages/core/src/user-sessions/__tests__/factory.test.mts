/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, expect, it } from "vitest";
import { createUserSessionStoreFactory, registerBuiltinUserSessionStores } from "../factory.mjs";

describe("UserSessionStoreFactory", () => {
	it("registerBuiltinUserSessionStores registers the 'memory' type", () => {
		const f = createUserSessionStoreFactory();
		registerBuiltinUserSessionStores(f);
		expect(f.registeredTypes()).toContain("memory");
	});

	it("built-in memory adapter is creatable", async () => {
		const f = createUserSessionStoreFactory();
		registerBuiltinUserSessionStores(f);
		const store = await f.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});

	it("unknown type throws AdapterFactoryError with UserSessionStore context", async () => {
		const f = createUserSessionStoreFactory();
		registerBuiltinUserSessionStores(f);
		await expect(f.create({ type: "unknown" })).rejects.toThrow(/UserSessionStore/);
	});

	it("built-in redis adapter is registered and creates instance", async () => {
		const f = createUserSessionStoreFactory();
		registerBuiltinUserSessionStores(f);
		// Provide an already-connected client to avoid dynamic import in tests.
		const fakeClient = {
			get: async () => null,
			set: async () => "OK",
			del: async () => 0,
		};
		const store = await f.create({
			type: "redis",
			client: fakeClient,
			keyPrefix: "x:",
		});
		expect(store.kind).toBe("redis");
	});
});
