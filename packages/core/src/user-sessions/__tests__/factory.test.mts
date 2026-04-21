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
import {
	createUserSessionStoreFactory,
	registerBuiltinUserSessionStores,
} from "../factory.mjs";

describe("UserSessionStoreFactory", () => {
	it("kind of the factory is 'userSessionStore'", () => {
		const f = createUserSessionStoreFactory();
		expect(f.kind).toBe("userSessionStore");
	});

	it("built-in memory adapter is creatable", async () => {
		const f = createUserSessionStoreFactory();
		registerBuiltinUserSessionStores(f);
		const store = await f.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});

	it("unknown type throws AdapterFactoryError", async () => {
		const f = createUserSessionStoreFactory();
		registerBuiltinUserSessionStores(f);
		await expect(f.create({ type: "unknown" })).rejects.toThrow(/unknown/);
	});
});
